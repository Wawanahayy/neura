#!/usr/bin/env node
/**
 * faucet.mjs — AUTO FLOW (login → account → visit → claim → balances)
 *
 * Config files:
 *   - .env        : minimal creds
 *   - config.yaml : flow, log, delays/spam/backoff, networks & tokens
 *   - api.json    : endpoints & request bodies
 *
 * Run:
 *   node faucet.mjs --fresh --debug
 */

import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import axios from 'axios';
import { ethers } from 'ethers';
import YAML from 'yaml';

const {
  PRIVATE_KEY,
  NEURA_RPC,
  PRIVY_BASE,
  NEURAVERSE_ORIGIN,
  DOMAIN,
  CHAIN_ID_NUM,
  DEBUG: ENV_DEBUG,
  SAFE_LOG_SECRETS = '0',

  SEPOLIA_RPC,           
  TOKEN_CONTRACT,        
} = process.env;

for (const k of ['PRIVATE_KEY','NEURA_RPC','PRIVY_BASE','NEURAVERSE_ORIGIN','DOMAIN','CHAIN_ID_NUM']) {
  if (!process.env[k]) {
    console.error(`[ENV] ${k} is required`);
    process.exit(1);
  }
}

const ARGV = new Set(process.argv.slice(2));
const DEBUG = ENV_DEBUG === '1' || ARGV.has('--debug');
const FRESH = ARGV.has('--fresh');

const wallet = new ethers.Wallet(PRIVATE_KEY);
const address = wallet.address;
const CHAIN_NAMESPACE = `eip155:${CHAIN_ID_NUM}`;

const ROOT = process.cwd();
const SESSION_FILE = path.resolve(ROOT, 'privy-session.json');
const CONFIG_YAML = path.resolve(ROOT, 'config.yaml');
const API_JSON    = path.resolve(ROOT, 'api.json');

const redact = (t, keep = 6) => {
  if (!t || typeof t !== 'string') return t;
  if (t.length <= keep * 2) return t;
  return `${t.slice(0, keep)}…${t.slice(-keep)}`;
};
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

function isHtmlLike(s) {
  if (!s || typeof s !== 'string') return false;
  const t = s.trimStart();
  return t.startsWith('<!DOCTYPE') || t.startsWith('<html') || t.includes('BAILOUT_TO_CLIENT_SIDE_RENDERING');
}
function previewBody(data, headers, max = 180, elideHtml = true) {
  const ctype = (headers?.['content-type'] || '').toLowerCase();
  if (elideHtml && (ctype.includes('text/html') || (typeof data === 'string' && isHtmlLike(data)))) {
    const len = typeof data === 'string' ? data.length : 0;
    return `[HTML omitted, ${len} chars]`;
  }
  if (data && typeof data === 'object') {
    const pick = {};
    if ('status' in data) pick.status = data.status;
    if ('message' in data) pick.message = data.message;
    if (data?.data && (typeof data.data === 'string' || typeof data.data === 'number')) pick.data = data.data;
    if (Object.keys(pick).length) return JSON.stringify(pick);
    try {
      const s = JSON.stringify(data);
      return s.length > max ? s.slice(0, max) + '…' : s;
    } catch {}
  }
  if (typeof data === 'string') {
    return data.length > max ? data.slice(0, max) + '…' : data;
  }
  return String(data ?? '');
}
function compactLine({ method, url, status, ms, data, headers, tag = '', maxBodyChars = 180, elideHtml = true }) {
  const p = previewBody(data, headers, maxBodyChars, elideHtml);
  const m = (method || 'REQ').toUpperCase();
  const s = status ? ` ${status}` : '';
  const t = typeof ms === 'number' ? ` (${ms}ms)` : '';
  return `${tag ? tag + ' ' : ''}${m} ${url}${s}${t} → ${p}`;
}

const DEFAULT_CFG = {
  flow: { whoami: true, visit: true },
  visitEvent: { type: 'game:visitValidatorHouse', payload: {} },
  claim: { spam: 1, intervalMs: 2500, maxAttempts: 6, baseDelayMs: 1000, maxDelayMs: 8000 },
  events: { sendClaimEvent: true },
  log: { level: 'info', maxBodyChars: 180, elideHtml: true, showHeaders: false },
  balances: {
    networks: [
      {
        name: 'Neura Testnet',
        rpcEnv: 'NEURA_RPC',
        rpc: null,
        nativeSymbol: 'ANKR',
        erc20: {
          symbol: 'ANKR',
          address: null,   
          decimals: 18
        }
      }
    ]
  }
};
const DEFAULT_API = {
  endpoints: {
    appBase: 'https://neuraverse.neuraprotocol.io',
    infraBase: 'https://neuraverse-testnet.infra.neuraprotocol.io',
    claimPaths: ['/api/faucet', '/api/faucet/claim', '/api/faucet/claim-testnet', '/api/claim'],
    eventsPath: '/api/events',
    accountPath: '/api/account'
  },
  claimBodies: [{ address: '$ADDRESS' }, { recipient: '$ADDRESS' }, { to: '$ADDRESS' }, {}]
};

function loadYaml(p, fallback) {
  try {
    const raw = fs.readFileSync(p, 'utf8');
    const cfg = YAML.parse(raw);
    if (DEBUG || (fallback.log?.level || 'info') === 'debug') console.log('[dbg] loaded', path.basename(p));
    return { ...fallback, ...cfg };
  } catch {
    if (DEBUG || (fallback.log?.level || 'info') === 'debug') console.log('[dbg] using default (no', path.basename(p)+')');
    return fallback;
  }
}
function loadJson(p, fallback) {
  try {
    const raw = fs.readFileSync(p, 'utf8');
    const obj = JSON.parse(raw);
    if (DEBUG || (fallback.log?.level || 'info') === 'debug') console.log('[dbg] loaded', path.basename(p));
    return { ...fallback, ...obj };
  } catch {
    if (DEBUG || (fallback.log?.level || 'info') === 'debug') console.log('[dbg] using default (no', path.basename(p)+')');
    return fallback;
  }
}
const CFG = loadYaml(CONFIG_YAML, DEFAULT_CFG);
const API = loadJson(API_JSON, DEFAULT_API);

const isDebug = () => (CFG.log?.level || 'info') === 'debug' || DEBUG;

const TANKR_DEFAULT = (TOKEN_CONTRACT && ethers.getAddress(TOKEN_CONTRACT))
  || ethers.getAddress('0xB88Ca91Fef0874828e5ea830402e9089aaE0bB7F');

for (const net of CFG.balances?.networks || []) {
  if (net.rpcEnv === 'NEURA_RPC') {
    net.rpc = NEURA_RPC;
    if (net.erc20 && !net.erc20.address) net.erc20.address = TANKR_DEFAULT;
  }
}
if (SEPOLIA_RPC) {
  CFG.balances.networks.push({
    name: 'Sepolia',
    rpcEnv: 'SEPOLIA_RPC',
    rpc: SEPOLIA_RPC,
    nativeSymbol: 'ETH',
    erc20: CFG.balances?.sepoliaToken || null, 
  });
}

const { PRIVY_APP_ID, PRIVY_CA_ID } = process.env;
for (const k of ['PRIVY_APP_ID','PRIVY_CA_ID']) {
  if (!process.env[k]) { console.error(`[ENV] ${k} is required`); process.exit(1); }
}
function loadSession() {
  if (FRESH) return {};
  try { return JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8')); }
  catch { return {}; }
}
function saveSession(s) {
  fs.writeFileSync(SESSION_FILE, JSON.stringify(s, null, 2));
  setAuthHeadersFromSession(s);
}

const http = axios.create({
  timeout: 25000,
  headers: {
    accept: 'application/json',
    'content-type': 'application/json',
    origin: NEURAVERSE_ORIGIN,
    referer: `${NEURAVERSE_ORIGIN}/`,
    'privy-app-id': PRIVY_APP_ID,
    'privy-ca-id': PRIVY_CA_ID,
    'privy-client': 'react-auth:2.25.0',
    'user-agent': 'Mozilla/5.0 (CLI Privy Bot)',
  },
  withCredentials: true,
});

http.interceptors.request.use(cfg => {
  cfg.meta = { start: Date.now() };
  if (isDebug()) {
    const headers = CFG.log?.showHeaders ? cfg.headers : {
      origin: cfg.headers?.origin,
      'privy-app-id': cfg.headers?.['privy-app-id'],
      authorization: cfg.headers?.authorization ? `Bearer ${redact(String(cfg.headers.authorization).slice(7))}` : undefined,
      Cookie: cfg.headers?.Cookie ? '(set)' : undefined,
    };
    console.log(compactLine({
      method: cfg.method, url: cfg.url, data: cfg.data, headers,
      tag: '⇢', maxBodyChars: CFG.log?.maxBodyChars, elideHtml: CFG.log?.elideHtml
    }));
  }
  return cfg;
});

http.interceptors.response.use(res => {
  const ms = Date.now() - (res.config.meta?.start || Date.now());
  if (isDebug()) {
    console.log(compactLine({
      method: res.config.method, url: res.config.url, status: res.status, ms,
      data: res.data, headers: res.headers, tag: '⇠', maxBodyChars: CFG.log?.maxBodyChars, elideHtml: CFG.log?.elideHtml
    }));
  }
  return res;
}, err => {
  const cfg = err.config || {};
  const ms = Date.now() - (cfg.meta?.start || Date.now());
  if (isDebug()) {
    console.log(compactLine({
      method: cfg.method, url: cfg.url, status: err.response?.status, ms,
      data: err.response?.data, headers: err.response?.headers, tag: '⇠',
      maxBodyChars: CFG.log?.maxBodyChars, elideHtml: CFG.log?.elideHtml
    }));
  }
  return Promise.reject(err);
});

function setAuthHeadersFromSession(sess) {
  const bearer = sess?.id_token || sess?.bearer || sess?.access_token;
  if (bearer) http.defaults.headers.common['authorization'] = `Bearer ${bearer}`;
  else delete http.defaults.headers.common['authorization'];

  const cookies = [];
  if (sess?.id_token)      cookies.push(`privy-id-token=${sess.id_token}`);
  if (sess?.access_token)  cookies.push(`privy-access-token=${sess.access_token}`);
  if (sess?.privy_token)   cookies.push(`privy-token=${sess.privy_token}`);
  if (sess?.refresh_token) cookies.push(`privy-refresh-token=${sess.refresh_token}`);
  if (sess?.session)       cookies.push(`privy-session=${sess.session}`);
  if (cookies.length) http.defaults.headers.common['Cookie'] = cookies.join('; ');
  else delete http.defaults.headers.common['Cookie'];

  if (isDebug()) {
    console.log('[dbg] setAuthHeadersFromSession',
      SAFE_LOG_SECRETS==='1'
        ? '(redacted)'
        : {
            bearer: bearer ? redact(bearer) : '',
            id_token: sess?.id_token ? redact(sess.id_token) : null,
            access_token: sess?.access_token ? redact(sess.access_token) : null,
            privy_token: sess?.privy_token ? redact(sess.privy_token) : null,
            refresh_token: sess?.refresh_token ? redact(sess.refresh_token) : null,
            session: sess?.session ? redact(sess.session) : null,
          }
    );
  }
}
setAuthHeadersFromSession(loadSession());


function buildSiweMessage({ domain, uri, address, statement, nonce, chainId, issuedAt }) {
  return `${domain} wants you to sign in with your Ethereum account:
${address}

${statement}

URI: ${uri}
Version: 1
Chain ID: ${chainId}
Nonce: ${nonce}
Issued At: ${issuedAt}
Resources:
- https://privy.io`;
}
async function siweInit(addr, { cleanHeaders = false } = {}) {
  if (cleanHeaders) {
    const { authorization, Cookie, ...rest } = http.defaults.headers.common;
    const tmp = axios.create({ ...http.defaults, headers: rest });
    return (await tmp.post(`${PRIVY_BASE}/api/v1/siwe/init`, { address: addr })).data;
  }
  return (await http.post(`${PRIVY_BASE}/api/v1/siwe/init`, { address: addr })).data;
}
async function siweAuthenticate({ message, signature }, { cleanHeaders = false } = {}) {
  const payload = {
    message,
    signature,
    chainId: CHAIN_NAMESPACE,
    walletClientType: 'rabby_wallet',
    connectorType: 'injected',
    mode: 'login-or-sign-up',
  };
  const doPost = async (strip = false) => {
    if (strip) {
      const { authorization, Cookie, ...rest } = http.defaults.headers.common;
      const tmp = axios.create({ ...http.defaults, headers: rest });
      return await tmp.post(`${PRIVY_BASE}/api/v1/siwe/authenticate`, payload);
    }
    return await http.post(`${PRIVY_BASE}/api/v1/siwe/authenticate`, payload);
  };
  let res;
  try { res = await doPost(false); }
  catch (e) {
    if (e.response?.status === 401 || e.response?.status === 403) {
      console.log('↻ authenticate retry without session headers…');
      res = await doPost(true);
    } else throw e;
  }

  const data = res.data;
  const setCookies = res.headers?.['set-cookie'] || [];
  const cookieBag = {};
  for (const sc of setCookies) {
    const m = String(sc).match(/^([^=]+)=([^;]+)/);
    if (!m) continue;
    cookieBag[m[1]] = m[2];
  }
  return { data, cookieBag };
}

async function ensureLogin() {
  const sess0 = loadSession();
  setAuthHeadersFromSession(sess0);

  try {
    await apiAccount();
    console.log('✅ session valid (already logged in)');
    return;
  } catch (e) {
    if (isDebug()) console.log('[dbg] account check failed (will login):', e.response?.status, e.response?.data?.message || e.message);
  }

  console.log('🔐 login (SIWE)…');
  let init;
  try { init = await siweInit(address); }
  catch (e) {
    if (e.response?.status === 401 || e.response?.status === 403) {
      console.log('↻ init retry without session headers…');
      init = await siweInit(address, { cleanHeaders: true });
    } else throw e;
  }

  const nonce = init?.nonce || ethers.hexlify(ethers.randomBytes(16)).slice(2);
  const message = buildSiweMessage({
    domain: DOMAIN,
    uri: NEURAVERSE_ORIGIN,
    address,
    statement: 'By signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.',
    nonce,
    chainId: CHAIN_ID_NUM,
    issuedAt: new Date().toISOString(),
  });
  if (isDebug()) {
    console.log('[dbg] SIWE message:\n' + message.split('\n').slice(0, 10).join('\n') + '\n…');
    console.log('[dbg] nonce =', nonce);
  }
  const signature = await wallet.signMessage(message);
  if (isDebug()) console.log('[dbg] signature =', redact(signature, 10));

  const { data: authData, cookieBag } = await siweAuthenticate({ message, signature });

  const session = loadSession();
  if (authData?.identity_token) session.id_token = authData.identity_token;
  if (authData?.token)          session.privy_token = authData.token;
  if (authData?.privy_access_token) session.access_token = authData.privy_access_token;
  if (authData?.refresh_token && authData.refresh_token !== 'deprecated') session.refresh_token = authData.refresh_token;

  if (cookieBag['privy-id-token'])      session.id_token = cookieBag['privy-id-token'];
  if (cookieBag['privy-access-token'])  session.access_token = cookieBag['privy-access-token'];
  if (cookieBag['privy-token'])         session.privy_token = cookieBag['privy-token'];
  if (cookieBag['privy-refresh-token']) session.refresh_token = cookieBag['privy-refresh-token'];
  if (cookieBag['privy-session'])       session.session = cookieBag['privy-session'];

  session.bearer = session.id_token || session.access_token || session.privy_token;
  if (!session.bearer) throw new Error('Login succeeded but identity/access token not found');

  saveSession(session);

  await apiAccount();
  console.log('✅ login ok');
}

function apiBases() {
  const { appBase, infraBase, eventsPath, accountPath } = API.endpoints;
  return {
    appBase, infraBase,
    eventsURL: `${infraBase}${eventsPath}`,
    accountURL: `${infraBase}${accountPath}`
  };
}
async function apiAccount() {
  const { accountURL } = apiBases();
  const { data } = await http.get(accountURL);
  return data;
}

async function sendVisitEventQuiet() {
  const { infraBase } = API.endpoints;
  const url = `${infraBase}${API.endpoints.eventsPath}`;
  const type = CFG.visitEvent?.type || 'game:visitValidatorHouse';
  const payload = CFG.visitEvent?.payload ?? {};
  try {
    await http.post(url, { type, payload });
  } catch (e) {
    if (isDebug()) console.log('[dbg] visit event error:', e.response?.status, e.response?.data || e.message);
  }
}

function buildBodies(to) {
  return (API.claimBodies || []).map(b => {
    if (!b || typeof b !== 'object') return {};
    const s = JSON.stringify(b).replaceAll('$ADDRESS', to);
    return JSON.parse(s);
  });
}

async function claimAtAppFaucet(to, { maxAttempts, baseDelayMs, maxDelayMs }) {
  const { appBase } = apiBases();
  const url = `${appBase}/api/faucet`;
  const bodies = buildBodies(to);

  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    for (const body of bodies) {
      try {
        const { data } = await http.post(url, body);
        return { url, body, data, attempt };
      } catch (e) {
        lastErr = e;
        const status = e.response?.status;
        const msg = typeof e.response?.data === 'string' ? e.response?.data : JSON.stringify(e.response?.data);
        if (isDebug()) console.log('[dbg] claim attempt', attempt, body, '→', status, msg);

        const lower = (e.response?.data?.message || msg || '').toLowerCase();
        if (status >= 500 || lower.includes('replacement transaction underpriced')) {
          const wait = Math.min(baseDelayMs * Math.pow(1.3, attempt - 1), maxDelayMs) + rand(0, 500);
          if (isDebug()) console.log('[dbg] retry in', wait, 'ms');
          await sleep(wait);
          continue;
        }
        if (status && status < 500) throw e;
      }
    }
  }
  throw lastErr || new Error('claimAtAppFaucet: exhausted');
}

async function tryClaim(to, opts) {
  const { sendClaimEvent } = CFG.events || {};
  if (sendClaimEvent) {
    await sendVisitEventQuiet();
  }

  try {
    return await claimAtAppFaucet(to, opts);
  } catch {
    if (isDebug()) console.log('[dbg] claimAtAppFaucet failed → fallback to claimPaths');
  }

  const { appBase, infraBase } = apiBases();
  const allBases = [appBase, infraBase];
  const paths = API.endpoints?.claimPaths || [];
  const bodies = buildBodies(to);

  let lastErr;
  for (const base of allBases) {
    for (const p of paths) {
      const url = `${base}${p}`;
      for (const body of bodies) {
        try {
          const { data } = await http.post(url, body);
          return { url, body, data, attempt: 'fallback' };
        } catch (e) {
          lastErr = e;
          if (isDebug()) {
            const s = e.response?.status;
            const msg = typeof e.response?.data === 'string' ? e.response?.data : JSON.stringify(e.response?.data);
            console.log('[dbg] fallback claim failed @', url, body, '→', s, msg);
          }
        }
      }
    }
  }
  throw lastErr || new Error('No claim endpoint succeeded');
}

const ERC20_ABI_MIN = [
  'function balanceOf(address) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
];

async function getNativeBalance(rpc, addr) {
  const provider = new ethers.JsonRpcProvider(rpc);
  const bal = await provider.getBalance(addr);
  return ethers.formatEther(bal);
}
async function getErc20Balance(rpc, tokenAddr, addr, decimalsHint) {
  const provider = new ethers.JsonRpcProvider(rpc);
  const c = new ethers.Contract(tokenAddr, ERC20_ABI_MIN, provider);
  const [raw, decimals, symbol] = await Promise.all([
    c.balanceOf(addr),
    typeof decimalsHint === 'number' ? decimalsHint : c.decimals(),
    c.symbol().catch(() => 'TOKEN'),
  ]);
  const d = typeof decimalsHint === 'number' ? decimalsHint : decimals;
  return { symbol, decimals: d, raw: raw.toString(), formatted: ethers.formatUnits(raw, d) };
}

function explainErc20Error(chainName, tokenAddr, err) {
  const low = (err?.message || '').toLowerCase();
  if (err?.code === 'BAD_DATA' || low.includes('could not decode result')) {
    return `ERC-20 balance unavailable on ${chainName}: cannot decode result. This usually means the token address ${tokenAddr} is wrong for this chain, the contract is not deployed, or it is non-standard.`;
  }
  if (err?.code === 'CALL_EXCEPTION') {
    return `ERC-20 balance call reverted on ${chainName}. The contract at ${tokenAddr} may not implement ERC-20 correctly on this chain.`;
  }
  return `ERC-20 balance error on ${chainName}: ${err?.message || 'unknown error'}`;
}

async function printBalances() {
  const nets = CFG.balances?.networks || [];
  for (const net of nets) {
    if (!net.rpc) continue;
    try {
      const native = await getNativeBalance(net.rpc, address);
      console.log(`💰 ${net.name} native (${net.nativeSymbol}) = ${native}`);
    } catch (e) {
      console.log(`⚠️ ${net.name} native balance failed:`, e.message);
    }
    if (net.erc20?.address) {
      const tokenAddr = ethers.getAddress(net.erc20.address);
      try {
        const erc = await getErc20Balance(net.rpc, tokenAddr, address, net.erc20.decimals);
        console.log(`🪙 ${net.name} ${erc.symbol} (ERC20 @ ${tokenAddr}) = ${erc.formatted}`);
      } catch (e) {
        console.log(explainErc20Error(net.name, tokenAddr, e));
      }
    }
  }
}

function printAccountSummary(acct) {
  console.log('👤 /api/account →');
  console.log(`  address       : ${acct?.address || '-'}`);
  const np = Number(acct?.neuraPoints ?? 0);
  console.log(`  neuraPoints   : ${isNaN(np) ? '-' : np}`);
  const tvm = Number(acct?.tradingVolume?.month ?? 0);
  const tva = Number(acct?.tradingVolume?.allTime ?? 0);
  console.log(`  tradingVolume : month=${isNaN(tvm) ? '-' : tvm} | allTime=${isNaN(tva) ? '-' : tva}`);
}

(async () => {
  try {
    console.log('Address :', address);
    console.log(`Networks enabled: Neura Testnet${SEPOLIA_RPC ? ', Sepolia' : ''}`);

    try {
      await ensureLogin();
    } catch (e) {
      console.error('❌ login failed:', e.response?.status || '', e.response?.data || e.message);
      process.exit(1);
    }

    if (CFG.flow?.whoami) {
      try {
        const acct = await apiAccount();
        printAccountSummary(acct);
      } catch (e) {
        console.log('⚠️ /api/account failed:', e.response?.status, e.response?.data ?? e.message);
      }
    }

    if (CFG.flow?.visit) {
      await sendVisitEventQuiet();
    }

    const { spam, intervalMs, maxAttempts, baseDelayMs, maxDelayMs } = CFG.claim;
    for (let i = 1; i <= Math.max(1, spam); i++) {
      try {
        const out = await tryClaim(address, { maxAttempts, baseDelayMs, maxDelayMs });
        const msg = out?.data?.message || '';
        const cd = out?.data?.data;
        if (/already received/i.test(msg) && cd && (cd.hours!=null || cd.minutes!=null || cd.seconds!=null)) {
          const h = cd.hours ?? 0, m = cd.minutes ?? 0, s = cd.seconds ?? 0;
          console.log(`🎁 claim [${i}/${spam}] → already claimed. Cooldown: ${h}h ${m}m ${s}s. Stop spamming.`);
        } else {
          console.log(`🎁 claim [${i}/${spam}] OK`);
          if (isDebug()) console.log('↩︎', previewBody(out.data, null, CFG.log?.maxBodyChars, CFG.log?.elideHtml));
        }
      } catch (e) {
        const status = e.response?.status;
        const msg = typeof e.response?.data === 'string' ? e.response?.data : JSON.stringify(e.response?.data);
        console.log(`❌ claim [${i}/${spam}] failed:`, status || '', msg || e.message);
      }
      if (i < spam) {
        const wait = Math.max(0, intervalMs) + rand(0, 500);
        if (isDebug()) console.log('[dbg] wait', wait, 'ms before next claim');
        await sleep(wait);
      }
    }

    await printBalances();

  } catch (e) {
    console.error('[fatal]', e.response?.status, e.response?.data ?? e.stack ?? e.message);
    process.exit(1);
  }
})();
