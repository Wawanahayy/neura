#!/usr/bin/env node
/**
 * auto.mjs — Orchestrator per-account (sekuensial)
 *
 * Default order:
 *   task.mjs → game.mjs → faucet.mjs → bridge.mjs → swap.mjs
 *
 * Fitur:
 * - Baca PRIVATE_KEYS_FILE & PROXIES_FILE
 * - Timeout per script, jeda antar script & antar akun
 * - Skip skrip via --skip=game,faucet atau pilih subset via --scripts=task,swap
 * - STOP_ON_FAIL (1 = stop sisa skrip utk akun tsb jika ada yang gagal)
 * - SIGINT/SIGTERM: kill proses anak & exit rapi
 *
 * ENV yang dipakai (opsional, dengan default):
 *   LOG_JSON=1
 *   BETWEEN_TASK_MS=1000
 *   BETWEEN_ACCOUNT_MS=2000
 *   SCRIPT_TIMEOUT_MS=120000
 *   STOP_ON_FAIL=1
 *   PRIVATE_KEYS_FILE=./privatekeys.txt
 *   PROXIES_FILE=./proxies.txt
 *
 * CLI:
 *   node auto.mjs
 *   node auto.mjs --scripts=task,game,swap
 *   node auto.mjs --skip=faucet,bridge --timeout=90000 --betweenTasks=1500 --betweenAccounts=3000
 *   node auto.mjs --startIndex=1 --endIndex=5           # batasi subset akun (1-based)
 *   node auto.mjs --fresh                               # teruskan flag ke child processes
 */

try { await import('dotenv').then(m => m.config()); } catch {}

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { Wallet } = require('ethers');

// ---------- args & env helpers ----------
function arg(name, def = null) {
  const a = process.argv.find(x => x.startsWith(`--${name}=`));
  if (a) return a.split('=').slice(1).join('=');          // --name=value
  const i = process.argv.indexOf(`--${name}`);            // --name (boolean)
  if (i !== -1) return true;
  return def;
}

const LOG_JSON            = (process.env.LOG_JSON ?? '1') === '1';
const BETWEEN_TASK_MS     = Number(arg('betweenTasks', process.env.BETWEEN_TASK_MS ?? 1000));
const BETWEEN_ACCOUNT_MS  = Number(arg('betweenAccounts', process.env.BETWEEN_ACCOUNT_MS ?? 2000));
const SCRIPT_TIMEOUT_MS   = Number(arg('timeout', process.env.SCRIPT_TIMEOUT_MS ?? 120000));
const STOP_ON_FAIL        = (process.env.STOP_ON_FAIL ?? '1') === '1';

const PRIVATE_KEYS_FILE   = process.env.PRIVATE_KEYS_FILE ?? './privatekeys.txt';
const PROXIES_FILE        = process.env.PROXIES_FILE ?? './proxies.txt';

// subset akun (1-based)
const START_INDEX         = Number(arg('startIndex', 1));
const END_INDEX           = Number(arg('endIndex', Infinity));

// filter scripts
const USER_SCRIPTS        = (arg('scripts', '') || '').toString().trim();
const USER_SKIP           = (arg('skip', '') || '').toString().trim();
// teruskan --fresh ke child jika ada
const FORWARD_FRESH       = !!arg('fresh', false);

const DEFAULT_ORDER = ['task', 'game', 'faucet', 'bridge', 'swap'];
const FILEMAP = {
  task:   'task.mjs',
  game:   'game.mjs',
  faucet: 'faucet.mjs',
  bridge: 'bridge.mjs',
  swap:   'swap.mjs',
};

function nowIso() { return new Date().toISOString(); }
function log(level, message, extra = {}) {
  if (!LOG_JSON) { console.log(`[${level}] ${message}`); return; }
  console.log(JSON.stringify({ ts: nowIso(), level, message, ...extra }));
}

// ---------- load keys & proxies ----------
function loadLines(file) {
  try {
    if (!fs.existsSync(file)) return [];
    return fs.readFileSync(file, 'utf8')
      .split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  } catch { return []; }
}
const PRIVATE_KEYS = loadLines(PRIVATE_KEYS_FILE);
if (!PRIVATE_KEYS.length) {
  log('error', `No private keys found. Put each key on a new line in ${PRIVATE_KEYS_FILE}`);
  process.exit(1);
}
const PROXIES = loadLines(PROXIES_FILE); // opsional

// ---------- pick scripts to run ----------
const SKIPS = new Set(
  USER_SKIP ? USER_SKIP.split(',').map(s => s.trim().toLowerCase()).filter(Boolean) : []
);
let ORDER = DEFAULT_ORDER.slice();
if (USER_SCRIPTS) {
  ORDER = USER_SCRIPTS.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  // validasi
  const invalid = ORDER.filter(x => !FILEMAP[x]);
  if (invalid.length) {
    log('error', `Unknown script keys in --scripts: ${invalid.join(', ')}`);
    process.exit(1);
  }
}
ORDER = ORDER.filter(k => !SKIPS.has(k));
if (!ORDER.length) {
  log('error', 'No scripts to run after applying --scripts/--skip');
  process.exit(1);
}

// ---------- spawn helper ----------
let CURRENT_CHILD = null;
function spawnScript(bin, args, env, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn(bin, args, {
      stdio: 'inherit',
      env: { ...process.env, ...env },
    });
    CURRENT_CHILD = child;

    let killedByTimeout = false;
    const t = setTimeout(() => {
      if (!child.killed) {
        killedByTimeout = true;
        try { child.kill('SIGTERM'); } catch {}
        setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 800);
      }
    }, timeoutMs);

    child.on('exit', (code, signal) => {
      clearTimeout(t);
      CURRENT_CHILD = null;
      resolve({ code: code ?? 0, signal, killedByTimeout });
    });
  });
}

// ---------- signal handling ----------
let ABORTING = false;
function abortHandler(name) {
  if (ABORTING) return;
  ABORTING = true;
  log('warn', `Received ${name}, shutting down...`);
  if (CURRENT_CHILD && !CURRENT_CHILD.killed) {
    try { CURRENT_CHILD.kill('SIGTERM'); } catch {}
    setTimeout(() => { try { CURRENT_CHILD.kill('SIGKILL'); } catch {} }, 800);
  }
  // beri sedikit waktu flush stdout
  setTimeout(() => process.exit(130), 500);
}
process.on('SIGINT',  () => abortHandler('SIGINT'));
process.on('SIGTERM', () => abortHandler('SIGTERM'));

// ---------- main per-account runner ----------
async function runForAccount(pk, index) {
  // derive address (tanpa print full PK)
  let address = '';
  try { address = new Wallet(pk).address; }
  catch { address = '(invalid-pk)'; }

  // tentukan proxy untuk akun ini (opsional)
  const proxyForThis = PROXIES.length ? PROXIES[(index - 1) % PROXIES.length] : (process.env.PROXY || process.env.SOCKS_PROXY || process.env.HTTPS_PROXY || '');

  log('info', `Account start`, { index, address, proxy: proxyForThis ? proxyForThis.split('://')[0] : 'none' });

  // ENV per child
  const childEnvBase = {
    PRIVATE_KEY: pk,
    PROXY: proxyForThis,           // agar cocok dg skrip lain yang baca PROXY
    HTTPS_PROXY: proxyForThis,     // sebagian lib pakai HTTPS_PROXY
    SOCKS_PROXY: proxyForThis,     // kalau socks
    // tambahkan marker indeks jika perlu dibaca anak
    AUTO_ACCOUNT_INDEX: String(index),
    AUTO_WALLET_ADDRESS: address,
  };

  // jalankan urutan skrip
  for (const key of ORDER) {
    const file = FILEMAP[key];
    const full = path.resolve(process.cwd(), file);
    if (!fs.existsSync(full)) {
      log('error', `Script file not found`, { file: full });
      if (STOP_ON_FAIL) {
        log('warn', `STOP_ON_FAIL=1 → skipping remaining scripts for account ${index}`);
        break;
      } else {
        continue;
      }
    }

    const args = [full];
    if (FORWARD_FRESH) args.push('--fresh');

    log('info', `Run script`, { account: index, script: file, timeoutMs: SCRIPT_TIMEOUT_MS });
    const { code, killedByTimeout } = await spawnScript(process.execPath, args, childEnvBase, SCRIPT_TIMEOUT_MS);

    if (code !== 0) {
      log('error', `Script failed`, { script: file, code, timeout: killedByTimeout });
      if (STOP_ON_FAIL) {
        log('warn', `STOP_ON_FAIL=1 → skipping remaining scripts for account ${index}`);
        break;
      }
    } else {
      log('info', `Script done`, { script: file, code });
    }

    if (ABORTING) return; // early out saat shutdown
    if (BETWEEN_TASK_MS > 0) {
      await new Promise(r => setTimeout(r, BETWEEN_TASK_MS));
    }
  }

  log('info', `Account done`, { index, address });
}

// ---------- runner ----------
(async () => {
  // batas subset akun (1-based)
  const total = PRIVATE_KEYS.length;
  const start = Math.max(1, START_INDEX);
  const end = Math.min(total, END_INDEX);

  if (start > end) {
    log('error', `Invalid range: startIndex=${START_INDEX} endIndex=${END_INDEX} (total=${total})`);
    process.exit(1);
  }

  log('info', `Plan`, {
    accounts: `${start}..${end} of ${total}`,
    order: ORDER.map(k => FILEMAP[k]),
    betweenTaskMs: BETWEEN_TASK_MS,
    betweenAccountMs: BETWEEN_ACCOUNT_MS,
    timeoutMs: SCRIPT_TIMEOUT_MS,
    stopOnFail: STOP_ON_FAIL,
  });

  for (let idx = start; idx <= end; idx++) {
    if (ABORTING) break;
    try {
      await runForAccount(PRIVATE_KEYS[idx - 1], idx);
    } catch (e) {
      const msg = e?.message || e?.code || String(e);
      log('error', `Account error`, { index: idx, error: msg });
    }
    if (idx < end && BETWEEN_ACCOUNT_MS > 0) {
      await new Promise(r => setTimeout(r, BETWEEN_ACCOUNT_MS));
    }
  }

  log('info', 'All done');
  process.exit(0);
})();
