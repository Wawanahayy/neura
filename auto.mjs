#!/usr/bin/env node
// auto.mjs — orchestrator cepat & robust (Neura)
// - SIWE login (retry 3x; hapus session per gagal)
// - Faucet claim tanpa /api/account gating
// - Panggil task/game/bridge/swap bila tersedia (ESM-safe)
// - Proxy: SOCKS / HTTPS via Agent
// - Cookie: tough-cookie (tanpa axios-cookiejar-support → kompatibel Agent)
// - Full debug: request/response headers, body, cookies, waktu
//   * SAFE_LOG_SECRETS=1 untuk redaksi bearer/cookie; 0 untuk raw

import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import axios from 'axios';
import YAML from 'yaml';
import { ethers } from 'ethers';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { pathToFileURL } from 'url';
import { CookieJar } from 'tough-cookie';
import { spawn } from 'node:child_process'; // ← tambah

// ===== required env =====
const REQ_VARS = [
  'PRIVY_BASE', 'NEURAVERSE_ORIGIN', 'DOMAIN', 'CHAIN_ID_NUM',
  'PRIVY_APP_ID', 'PRIVY_CA_ID'
];
for (const k of REQ_VARS) {
  if (!process.env[k]) { console.error(`[ENV] ${k} is required`); process.exit(1); }
}

const {
  NEURA_RPC,
  SEPOLIA_RPC,

  PRIVY_BASE,
  NEURAVERSE_ORIGIN,
  DOMAIN,
  CHAIN_ID_NUM,
  PRIVY_APP_ID,
  PRIVY_CA_ID,

  PRIVATE_KEY,
  PRIVATE_KEYS_FILE,
  PROXIES_FILE,
  PROXY,
  SOCKS_PROXY,
  HTTPS_PROXY,

  ALLOW_NO_PROXY_ON_SIWE = '1',
  DEBUG: ENV_DEBUG,
  SAFE_LOG_SECRETS = '1',
} = process.env;

const ARGV  = new Set(process.argv.slice(2));
const DEBUG = ENV_DEBUG === '1' || ARGV.has('debug');
const FRESH = ARGV.has('fresh');

// ===== load config & api =====
const ROOT        = process.cwd();
const CONFIG_YAML = path.resolve(ROOT, 'config.yaml');
const API_JSON    = path.resolve(ROOT, 'api.json');
if (!fs.existsSync(CONFIG_YAML)) { console.error('Missing config.yaml'); process.exit(1); }
if (!fs.existsSync(API_JSON))    { console.error('Missing api.json'); process.exit(1); }

const CFG = YAML.parse(fs.readFileSync(CONFIG_YAML,'utf8'));
const API = JSON.parse(fs.readFileSync(API_JSON,'utf8'));

// ===== (NEW) index.js token function discovery =====
let INDEX_TOKEN_FN = null;
try {
  const idxPath = path.resolve(ROOT, 'index.js');
  if (fs.existsSync(idxPath)) {
    const idxMod = await import(pathToFileURL(idxPath).href);
    INDEX_TOKEN_FN = idxMod.getTurnstileToken || idxMod.solveTurnstileToken || idxMod.default || null;
  }
} catch { /* ignore */ }

// ===== helpers =====
function get(obj, pathStr, def) { try { return pathStr.split('.').reduce((o,k)=> (o && k in o) ? o[k] : undefined, obj) ?? def; } catch { return def; } }
const sleep  = (ms)=> new Promise(r=>setTimeout(r,ms));
const redact = (t, keep=6) => (!t || typeof t!=='string' || t.length<=keep*2) ? t : `${t.slice(0,keep)}…${t.slice(-keep)}`;
const bool   = (x)=> !!x;
const num    = (x)=> (Number.isFinite(Number(x)) ? Number(x) : 0);

// ===== logging =====
const LOG_LEVEL = String(get(CFG,'log.level','info')).toLowerCase(); // debug|info|silent
const L = {
  debug: (...a)=> { if (LOG_LEVEL==='debug') console.log(...a); },
  info:  (...a)=> { if (LOG_LEVEL!=='silent') console.log(...a); },
  warn:  (...a)=> { if (LOG_LEVEL!=='silent') console.log(...a); },
  err:   (...a)=> console.error(...a),
};

// ===== cfg params =====
const HTTP_TIMEOUT   = num(get(CFG,'net.timeoutMs', 45000));
const NET_RETRIES    = num(get(CFG,'net.retries', 4));
const NET_BASE_DELAY = num(get(CFG,'net.baseDelayMs', 300));
const NET_BACKOFF    = num(get(CFG,'net.backoff', 1.8));
const NET_JITTER     = num(get(CFG,'net.jitterMs', 200));

const LOGIN_TRIES            = num(get(CFG,'login.tries', 3));
const POST_LOGIN_DELAY_MS    = num(get(CFG,'flow.postLoginDelayMs', 100));
const POST_SESSION_DELAY_MS  = num(get(CFG,'flow.postSessionDelayMs', 0));
const BETWEEN_ACCOUNTS_MS    = num(get(CFG,'flow.betweenAccountsMs', 1000));
const FLOW_WHOAMI            = bool(get(CFG,'flow.whoami', true));
const FLOW_VISIT             = bool(get(CFG,'flow.visit',  true));
const VISIT_EVENT_T          = String(get(CFG,'visitEvent.type','game:visitValidatorHouse'));
const VISIT_EVENT_P          = get(CFG,'visitEvent.payload', {});

// Faucet tuning via YAML
const CLAIM_CFG = get(CFG,'claim', {});
const CLAIM_ATTEMPTS   = num(CLAIM_CFG.attempts ?? CLAIM_CFG.maxAttempts ?? 8);
const CLAIM_FACTOR     = Number(CLAIM_CFG.factor ?? 1.6);
const CLAIM_JITTER     = num(CLAIM_CFG.jitterMs ?? 600);
const CLAIM_INTERVAL   = num(CLAIM_CFG.intervalMs ?? 1500);
const CLAIM_SPAM       = num(CLAIM_CFG.spam ?? 0);
const CLAIM_RETRY_FOREVER = Boolean(CLAIM_CFG.retryForever ?? false);
const STOP_ON_STRINGS  = (Array.isArray(CLAIM_CFG.stopOn) ? CLAIM_CFG.stopOn : []).map(s=>String(s||'').toLowerCase());

// ===== sessions (per-wallet) =====
const SESS_ROOT = path.resolve(ROOT, 'sessions');
fs.mkdirSync(SESS_ROOT, { recursive: true });
const accountDir  = (addr) => path.join(SESS_ROOT, addr.toLowerCase());
const sessionFile = (addr) => path.join(accountDir(addr), 'session.json');
function ensureAccountDir(addr){ fs.mkdirSync(accountDir(addr), { recursive: true }); }
function deleteSessionTree(addr){ try { fs.rmSync(accountDir(addr), { recursive: true, force: true }); } catch {} }

// ===== proxy & cookie =====
function createAgentFromProxy(proxyUrl) {
  if (!proxyUrl) return { httpAgent: undefined, httpsAgent: undefined };
  const p = String(proxyUrl).trim().toLowerCase();
  if (p.startsWith('socks')) { const agent = new SocksProxyAgent(proxyUrl); return { httpAgent: agent, httpsAgent: agent }; }
  const agent = new HttpsProxyAgent(proxyUrl);
  return { httpAgent: agent, httpsAgent: agent };
}
function maskProxyForDisplay(proxyUrl) {
  if (!proxyUrl) return 'no-proxy';
  try { const u = new URL(proxyUrl); return (u.protocol || '').replace(':','').toLowerCase() || 'proxy'; }
  catch { const l = String(proxyUrl).toLowerCase(); return l.startsWith('socks') ? l.split(':')[0] : (l.startsWith('http') ? l.split(':')[0] : 'proxy'); }
}

// CookieJar attach (manual, kompatibel dengan custom Agent)
function attachCookieJar(instance, jar) {
  instance.__cookieJar = jar;

  instance.interceptors.request.use(async (cfg) => {
    try {
      const full = cfg.baseURL ? new URL(cfg.url, cfg.baseURL).toString() : cfg.url;
      const cookie = await jar.getCookieString(full);
      if (cookie) {
        if (!cfg.headers) cfg.headers = {};
        if (!cfg.headers.Cookie && !cfg.headers.cookie) {
          cfg.headers.Cookie = cookie;
        }
      }
    } catch {}
    return cfg;
  });

  instance.interceptors.response.use(async (res) => {
    try {
      const setCookie = res.headers?.['set-cookie'];
      if (setCookie && Array.isArray(setCookie)) {
        const full = res.config.baseURL ? new URL(res.config.url, res.config.baseURL).toString() : res.config.url;
        for (const sc of setCookie) {
          await jar.setCookie(sc, full);
        }
      }
    } catch {}
    return res;
  });
}

// ===== axios w/ retry + full-debug =====
function axiosWithRetry({ origin, proxyUrl }) {
  const agent = createAgentFromProxy(proxyUrl);
  const instance = axios.create({
    timeout: HTTP_TIMEOUT,
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      origin,
      referer: `${origin}/`,
      'privy-app-id': PRIVY_APP_ID,
      'privy-ca-id':  PRIVY_CA_ID,
      'privy-client': 'react-auth:2.25.0',
      'user-agent': 'Mozilla/5.0 (CLI Privy Bot)',
    },
    withCredentials: true,
    httpAgent: agent.httpAgent,
    httpsAgent: agent.httpsAgent,
    proxy: false,
    validateStatus: () => true,
  });

  // cookie jar
  const jar = new CookieJar();
  attachCookieJar(instance, jar);

  instance.interceptors.request.use(cfg=>{ cfg.meta = { start: Date.now() }; return cfg; });

  // retries
  instance.interceptors.response.use(async res=>{
    const cfg = res.config || {};
    if (cfg.__noRetry || cfg.noRetry) return res;
    const s = res.status;
    const retriable = s===429 || (s>=500 && s<600);
    if (retriable && (cfg.__retryCount||0) < NET_RETRIES) {
      cfg.__retryCount = (cfg.__retryCount||0) + 1;
      const delay = Math.floor(NET_BASE_DELAY * Math.pow(NET_BACKOFF, cfg.__retryCount - 1) + Math.random()*NET_JITTER);
      if (LOG_LEVEL==='debug') console.log(`network retry ${cfg.__retryCount}/${NET_RETRIES} in ${delay}ms → ${cfg.url} (status ${s})`);
      await sleep(delay);
      return instance(cfg);
    }
    return res;
  }, async err=>{
    const cfg = err.config || {};
    if (cfg?.__noRetry || cfg?.noRetry) return Promise.reject(err);
    const retriableCode = new Set(['ECONNABORTED','ECONNRESET','ETIMEDOUT','EAI_AGAIN','ECONNREFUSED','EPIPE']);
    if ((cfg.__retryCount||0) < NET_RETRIES && (retriableCode.has(err.code) || /socket hang up/i.test(err.message||''))) {
      cfg.__retryCount = (cfg.__retryCount||0) + 1;
      const delay = Math.floor(NET_BASE_DELAY * Math.pow(NET_BACKOFF, cfg.__retryCount - 1) + Math.random()*NET_JITTER);
      if (LOG_LEVEL==='debug') console.log(`network retry ${cfg.__retryCount}/${NET_RETRIES} in ${delay}ms → ${cfg.url} (${err.code||err.message})`);
      await sleep(delay);
      return instance(cfg);
    }
    return Promise.reject(err);
  });

  // full debug logs
  if (LOG_LEVEL==='debug' || DEBUG) {
    instance.interceptors.request.use(cfg=>{
      let auth = cfg.headers?.authorization ?? cfg.headers?.Authorization;
      let cookieHdr = cfg.headers?.Cookie || cfg.headers?.cookie;
      const proxyDisp = maskProxyForDisplay(proxyUrl);

      const showHeaders = { ...cfg.headers };
      if (SAFE_LOG_SECRETS === '1') {
        if (auth)  showHeaders.authorization = `Bearer ${redact(String(auth).replace(/^Bearer\s+/i,'').trim())}`;
        if (showHeaders.Authorization) showHeaders.Authorization = showHeaders.authorization;
        if (cookieHdr) {
          showHeaders.Cookie = '(set)';
          showHeaders.cookie = '(set)';
        }
      }
      console.log(`⇢ [proxy=${proxyDisp}] ${String(cfg.method||'REQ').toUpperCase()} ${cfg.url}`);
      console.log('[req.headers]', JSON.stringify(showHeaders, null, 2));
      if (cfg.data !== undefined) {
        let bodyToShow = cfg.data;
        try { if (typeof bodyToShow === 'string') bodyToShow = JSON.parse(bodyToShow); } catch {}
        if (SAFE_LOG_SECRETS === '1') {
          // minimal masking fields umum
          bodyToShow = JSON.parse(JSON.stringify(bodyToShow));
          if (bodyToShow?.signature) bodyToShow.signature = redact(String(bodyToShow.signature), 10);
          if (bodyToShow?.message && /privy|token|nonce/i.test(bodyToShow.message)) {
            // biarkan full (kamu minta full debug). Matikan dengan SAFE_LOG_SECRETS=1 jika mau mask.
          }
        }
        console.log('[req.body]', JSON.stringify(bodyToShow, null, 2));
      }
      return cfg;
    });

    const logResp = (res, err)=> {
      const ms = Date.now() - (res?.config?.meta?.start || Date.now());
      const proxyDisp = maskProxyForDisplay(proxyUrl);
      const status = res?.status ?? err?.response?.status ?? '-';
      const method = String(res?.config?.method || err?.config?.method || 'REQ').toUpperCase();
      const url = res?.config?.url || err?.config?.url;
      console.log(`⇠ [proxy=${proxyDisp}] ${method} ${url} ${status} (${ms}ms)`);

      const headers = res?.headers || err?.response?.headers || {};
      const showHeaders = { ...headers };
      if (SAFE_LOG_SECRETS === '1') {
        if (showHeaders['set-cookie']) showHeaders['set-cookie'] = showHeaders['set-cookie'].map(()=>'(set-cookie)');
      }
      console.log('[res.headers]', JSON.stringify(showHeaders, null, 2));

      const setCookie = headers['set-cookie'];
      if (setCookie) {
        const list = SAFE_LOG_SECRETS==='1' ? setCookie.map(()=>'(set-cookie)') : setCookie;
        console.log('[res.set-cookie]', JSON.stringify(list, null, 2));
      }

      let body = res?.data ?? err?.response?.data;
      if (body !== undefined) {
        console.log('[res.body]', (typeof body==='string' ? body : JSON.stringify(body, null, 2)));
      }
    };

    instance.interceptors.response.use(
      (res)=>{ logResp(res); return res; },
      (err)=>{ logResp(err?.response, err); return Promise.reject(err); }
    );
  }

  return instance;
}

// ===== (NEW) Turnstile token resolver via index.js =====
async function resolveTurnstileTokenViaCli() {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, ['index.js'], { stdio: ['ignore', 'pipe', 'inherit'] });
    let buf = '';
    p.stdout.on('data', d => { buf += d.toString(); });
    p.on('close', code => {
      const out = buf.trim();
      if (code === 0 && out) return resolve(out);
      reject(new Error(`index.js exited ${code} or empty token`));
    });
  });
}
async function resolveTurnstileToken() {
  if (typeof INDEX_TOKEN_FN === 'function') {
    const tok = await INDEX_TOKEN_FN();
    if (!tok || typeof tok !== 'string') throw new Error('index.js token fn returned empty');
    return tok.trim();
  }
  return await resolveTurnstileTokenViaCli();
}

// ===== (NEW) POST helper w/ Turnstile auto-inject =====
async function postWithTurnstileIfNeeded(client, url, body, cfg = {}) {
  // first try
  let res = await client.post(url, body, cfg);

  const need =
    res.status === 401 || res.status === 403 ||
    /turnstile|captcha/i.test(String(res.data ?? ''));

  if (!need) return res;

  // solve & retry
  const token = await resolveTurnstileToken();
  const body2 = { ...body, 'cf-turnstile-response': token };
  const cfg2 = { ...cfg, __noRetry: cfg.__noRetry ?? false };
  return await client.post(url, body2, cfg2);
}

// ===== SIWE helpers =====
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

async function siweInit(http, address, { cleanHeaders=false } = {}) {
  const url = `${PRIVY_BASE}/api/v1/siwe/init`;
  if (cleanHeaders) {
    const { authorization, Authorization, Cookie, cookie, ...rest } = http.defaults.headers.common || {};
    const tmp = axios.create({ ...http.defaults, headers: rest, timeout: HTTP_TIMEOUT, proxy: false, validateStatus: () => true });
    if (http.defaults.httpsAgent) tmp.defaults.httpsAgent = http.defaults.httpsAgent;
    if (http.defaults.httpAgent)  tmp.defaults.httpAgent  = http.defaults.httpAgent;
    if (http.__cookieJar) attachCookieJar(tmp, http.__cookieJar);
    const res = await tmp.post(url, { address });
    if (res.status >= 400) throw new Error(`siwe.init ${res.status}`);
    return res.data;
  }
  const res = await http.post(url, { address });
  if (res.status >= 400) throw new Error(`siwe.init ${res.status}`);
  return res.data;
}

async function siweAuthenticate(http, { message, signature }) {
  const url = `${PRIVY_BASE}/api/v1/siwe/authenticate`;
  const payload = {
    message, signature,
    chainId: `eip155:${CHAIN_ID_NUM}`,
    walletClientType:'rabby_wallet',
    connectorType:'injected',
    mode:'login-or-sign-up'
  };

  // 1) coba dengan client utama, auto-inject turnstile saat perlu
  let res = await postWithTurnstileIfNeeded(http, url, payload);

  // 2) kalau masih 401/403 → coba "strip" header auth/cookie default dan ulangi
  if (res.status === 401 || res.status === 403) {
    const { authorization, Authorization, Cookie, cookie, ...rest } = http.defaults.headers.common || {};
    const tmp = axios.create({ ...http.defaults, headers: rest, timeout: HTTP_TIMEOUT, proxy: false, validateStatus: () => true });
    if (http.defaults.httpsAgent) tmp.defaults.httpsAgent = http.defaults.httpsAgent;
    if (http.defaults.httpAgent)  tmp.defaults.httpAgent  = http.defaults.httpAgent;
    if (http.__cookieJar) attachCookieJar(tmp, http.__cookieJar);
    res = await postWithTurnstileIfNeeded(tmp, url, payload);
  }

  if (res.status >= 400) throw new Error(`siwe.authenticate ${res.status}`);

  const setCookies = res.headers?.['set-cookie'] || [];
  const bag = {};
  for (const sc of setCookies) {
    const m = String(sc).match(/^([^=]+)=([^;]+)/);
    if (m) bag[m[1]] = m[2];
  }
  return { data: res.data, cookieBag: bag };
}

function setAuthHeadersFromSession(http, sess){
  const bearer = sess?.id_token || sess?.bearer || sess?.access_token || sess?.privy_token;
  if (bearer) http.defaults.headers.common['authorization'] = `Bearer ${bearer}`; else delete http.defaults.headers.common['authorization'];
  // Note: Cookie header akan dikelola jar; tapi kita simpan juga kalau dari session
  const cookies = [];
  if (sess?.id_token)       cookies.push(`privy-id-token=${sess.id_token}`);
  if (sess?.access_token)   cookies.push(`privy-access-token=${sess.access_token}`);
  if (sess?.privy_token)    cookies.push(`privy-token=${sess.privy_token}`);
  if (sess?.refresh_token)  cookies.push(`privy-refresh-token=${sess.refresh_token}`);
  if (sess?.session)        cookies.push(`privy-session=${sess.session}`);
  // Jangan paksa set ke header—biarkan jar yang pegang.
  if (LOG_LEVEL==='debug' || DEBUG) {
    const show = SAFE_LOG_SECRETS==='1'
      ? { bearer: redact(bearer||''), cookies: cookies.length ? '(set via jar)' : '(none)' }
      : { bearer, cookies: cookies.join('; ') || '(none, jar active)' };
    console.log('[dbg] session.set', show);
  }
}

// ===== API endpoints =====
const baseInfra = get(API,'endpoints.infraBase','');
const baseApp   = get(API,'endpoints.appBase','');
const paths = {
  events:  get(API,'endpoints.eventsPath','/api/events'),
};

// ===== event (fast) =====
async function postEventFast(http, type, payload={}) {
  try {
    await http.post(`${baseInfra}${paths.events}`, { type, payload }, { timeout: 1200, noRetry: true });
  } catch {}
}

// ===== keys & proxies =====
function getPrivateKeys() {
  if (PRIVATE_KEYS_FILE && fs.existsSync(PRIVATE_KEYS_FILE)) {
    const lines = fs.readFileSync(PRIVATE_KEYS_FILE,'utf8').split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
    if (lines.length) return lines;
  }
  if (PRIVATE_KEY) return [PRIVATE_KEY.trim()];
  console.error('No private key found. Set PRIVATE_KEYS_FILE or PRIVATE_KEY in .env');
  process.exit(1);
}
function getProxies() {
  if (PROXIES_FILE && fs.existsSync(PROXIES_FILE)) {
    return fs.readFileSync(PROXIES_FILE,'utf8').split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
  }
  const envSingle = PROXY || SOCKS_PROXY || HTTPS_PROXY || '';
  return envSingle ? [envSingle] : [];
}

// ===== faucet claim (no /api/account gating) =====
function looksStop(msg='') {
  const m = String(msg||'').toLowerCase();
  return STOP_ON_STRINGS.some(s => m.includes(s));
}
function makeFaucetEndpoints() {
  const list = [];
  const infra = baseInfra?.replace(/\/+$/,'') || '';
  const app   = baseApp?.replace(/\/+$/,'')   || '';
  const rels  = ['/api/faucet/claim', '/api/faucet', '/api/faucet/claim-testnet'];
  for (const r of rels) if (infra) list.push(`${infra}${r}`);
  for (const r of rels) if (app)   list.push(`${app}${r}`);
  list.push('https://neuraverse.neuraprotocol.io/api/faucet/claim');
  list.push('https://neuraverse.neuraprotocol.io/api/faucet');
  list.push('https://neuraverse.neuraprotocol.io/api/faucet/claim-testnet');
  return Array.from(new Set(list));
}
async function faucetClaim(http, address) {
  L.info('→ faucet: start (no account check; YAML-controlled retry)');
  const endpoints = makeFaucetEndpoints();

  const maxAttempts = CLAIM_RETRY_FOREVER ? Number.MAX_SAFE_INTEGER : Math.max(1, CLAIM_ATTEMPTS);
  let attempt = 0, delay = Math.max(200, CLAIM_INTERVAL);

  while (attempt < maxAttempts) {
    attempt++;
    for (const url of endpoints) {
      try {
        let res = await http.post(url, {}, { timeout: 4000 });
        if (res.status === 404 && /\/api\/faucet$/.test(url)) {
          L.debug(`↻ retry with address body → [POST] ${url}`);
          res = await http.post(url, { address }, { timeout: 4000 });
        }
        if (res.status >= 200 && res.status < 300) {
          L.info(`✅ faucet claim success @ ${url} [POST]`);
          return true;
        }
        const body = res.data;
        const msg  = typeof body==='object' ? (body?.message || JSON.stringify(body)) : String(body||'');
        if (res.status === 404) {
          L.debug(`— FAUCET [POST] ${url} 404 → NOT_FOUND…`);
          continue;
        }
        if (looksStop(msg)) {
          L.info(`⛔ faucet claim stopped by stopOn rule: ${JSON.stringify(msg)}`);
          return false;
        }
        L.debug(`— FAUCET [POST] ${url} ${res.status} → ${msg?.slice?.(0,140) || msg}`);
      } catch (e) {
        const msg = e?.message || 'error';
        if (/abort|timeout|ECONN|reset|EPIPE/i.test(msg)) {
          L.debug(`— FAUCET [POST] ${url} network → ${msg}`);
        } else {
          L.debug(`— FAUCET [POST] ${url} error → ${msg}`);
        }
      }
    }

    if (CLAIM_SPAM > 0 && attempt === 1) {
      for (let i=0;i<CLAIM_SPAM;i++){
        for (const url of endpoints) {
          http.post(url, { address }, { timeout: 2500 }).catch(()=>{});
        }
        await sleep( Math.max(80, Math.floor(CLAIM_INTERVAL/2)) );
      }
    }

    if (!CLAIM_RETRY_FOREVER && attempt >= maxAttempts) break;
    const jitter = Math.floor(Math.random()*CLAIM_JITTER);
    L.debug(`↻ faucet retry ${attempt}/${maxAttempts} in ${delay+jitter}ms`);
    await sleep(delay + jitter);
    delay = Math.min(delay * CLAIM_FACTOR, 20000);
  }
  L.info('❌ faucet claim: exhausted attempts');
  return false;
}

// ===== module runner (task/game/bridge/swap) =====
async function tryRunModule(modName, ctx) {
  const fullPath = path.resolve(ROOT, `${modName}.mjs`);
  if (!fs.existsSync(fullPath)) {
    L.debug(`— ${modName}.mjs (skip: not found)`);
    return;
  }
  const fileUrl = pathToFileURL(fullPath).href;
  try {
    const mod = await import(fileUrl);
    const fn =
      (typeof mod.run === 'function') ? mod.run
      : (mod.default && typeof mod.default.run === 'function') ? mod.default.run
      : (typeof mod.default === 'function') ? mod.default
      : (typeof mod.main === 'function') ? mod.main
      : null;
    if (!fn) {
      L.debug(`— ${modName}.mjs (skip: no run/default/main export)`);
      return;
    }
    await fn(ctx);
  } catch (e) {
    L.warn(`— ${modName}.mjs error: ${e.message || e}`);
  }
}

// ===== per-account flow =====
async function runForAccount(pk, index, proxyForThisAccount) {
  let wallet;
  try { wallet = new ethers.Wallet(pk); }
  catch (e) {
    L.err(`\n== AUTO Account #${index} (invalid key) | proxy=${maskProxyForDisplay(proxyForThisAccount)} ==`);
    L.err(`SIWE login failed: ${e.message}`);
    return;
  }
  const address   = wallet.address;
  const safeProxy = maskProxyForDisplay(proxyForThisAccount);
  ensureAccountDir(address);
  const SESSION_FILE = sessionFile(address);

  const http = axiosWithRetry({ origin: NEURAVERSE_ORIGIN, proxyUrl: proxyForThisAccount });
  const loadSession = ()=> {
    if (FRESH) return {};
    try { return JSON.parse(fs.readFileSync(SESSION_FILE,'utf8')); } catch { return {}; }
  };
  const saveSession = (s)=> {
    ensureAccountDir(address);
    fs.writeFileSync(SESSION_FILE, JSON.stringify(s,null,2));
    setAuthHeadersFromSession(http,s);
  };

  setAuthHeadersFromSession(http, loadSession());

  L.info(`\n== AUTO Account #${index} ${address} | proxy=${safeProxy} ==`);
  if (FLOW_WHOAMI) {
    L.info(`Address: ${address}`);
    L.info(`Networks: Neura Testnet${SEPOLIA_RPC ? ', Sepolia' : ''}`);
  }

  // SIWE login
  let authed = !!http.defaults.headers.common['authorization'];
  if (!authed || FRESH) {
    let lastErr;
    for (let i=0;i<LOGIN_TRIES;i++){
      try {
        const init = await siweInit(http, address).catch(async e=>{
          if (e.message?.includes('siwe.init 401') || e.message?.includes('siwe.init 403')) {
            return await siweInit(http, address, { cleanHeaders:true });
          }
          throw e;
        });
        const nonce = init?.nonce || ethers.hexlify(ethers.randomBytes(16)).slice(2);
        const message = buildSiweMessage({
          domain: DOMAIN, uri: NEURAVERSE_ORIGIN, address,
          statement: 'By signing, you are proving you own this wallet and logging in.',
          nonce, chainId: CHAIN_ID_NUM, issuedAt: new Date().toISOString()
        });
        const signature = await wallet.signMessage(message);
        const { data: authData, cookieBag } = await siweAuthenticate(http, { message, signature });

        const sess = {};
        if (authData?.identity_token)     sess.id_token = authData.identity_token;
        if (authData?.privy_access_token) sess.access_token = authData.privy_access_token;
        if (authData?.token)              sess.privy_token = authData.token;
        if (authData?.refresh_token && authData.refresh_token !== 'deprecated') sess.refresh_token = authData.refresh_token;
        if (cookieBag['privy-id-token'])      sess.id_token = cookieBag['privy-id-token'];
        if (cookieBag['privy-access-token'])  sess.access_token = cookieBag['privy-access-token'];
        if (cookieBag['privy-token'])         sess.privy_token = cookieBag['privy-token'];
        if (cookieBag['privy-refresh-token']) sess.refresh_token = cookieBag['privy-refresh-token'];
        if (cookieBag['privy-session'])       sess.session = cookieBag['privy-session'];
        sess.bearer = sess.id_token || sess.access_token || sess.privy_token;
        if (!sess.bearer) throw new Error('Login ok but no token');
        saveSession(sess);

        L.info('✅ login ok');
        if (POST_LOGIN_DELAY_MS > 0) { L.debug(`⏳ post-login delay ${POST_LOGIN_DELAY_MS}ms...`); await sleep(POST_LOGIN_DELAY_MS); }
        authed = true;
        break;
      } catch (e) {
        lastErr = e;
        if ((/ECONN|timeout|reset|EPIPE|EAI_AGAIN/i.test(e.message || '') || /401/.test(e.message || '')) && ALLOW_NO_PROXY_ON_SIWE==='1' && proxyForThisAccount) {
          try {
            const httpNoProxy = axiosWithRetry({ origin: NEURAVERSE_ORIGIN, proxyUrl: null });
            const init = await siweInit(httpNoProxy, address, { cleanHeaders:true });
            const nonce = init?.nonce || ethers.hexlify(ethers.randomBytes(16)).slice(2);
            const message = buildSiweMessage({
              domain: DOMAIN, uri: NEURAVERSE_ORIGIN, address,
              statement: 'By signing, you are proving you own this wallet and logging in.',
              nonce, chainId: CHAIN_ID_NUM, issuedAt: new Date().toISOString()
            });
            const signature = await wallet.signMessage(message);
            const { data: authData, cookieBag } = await siweAuthenticate(httpNoProxy, { message, signature });
            const sess = {};
            if (authData?.identity_token)     sess.id_token = authData.identity_token;
            if (authData?.privy_access_token) sess.access_token = authData.privy_access_token;
            if (authData?.token)              sess.privy_token = authData.token;
            if (cookieBag['privy-id-token'])      sess.id_token = cookieBag['privy-id-token'];
            if (cookieBag['privy-access-token'])  sess.access_token = cookieBag['privy-access-token'];
            if (cookieBag['privy-token'])         sess.privy_token = cookieBag['privy-token'];
            if (cookieBag['privy-session'])       sess.session = cookieBag['privy-session'];
            sess.bearer = sess.id_token || sess.access_token || sess.privy_token;
            if (!sess.bearer) throw new Error('Login ok but no token (no-proxy)');
            saveSession(sess);
            L.info('✅ login ok (no-proxy fallback)');
            authed = true;
            break;
          } catch (e2) {
            lastErr = e2;
          }
        }
        const backoff = Math.floor(NET_BASE_DELAY * Math.pow(NET_BACKOFF, i) + Math.random()*NET_JITTER);
        L.warn(`SIWE login failed (${i+1}/${LOGIN_TRIES}) → ${e.message || e}; retrying in ${backoff}ms`);
        deleteSessionTree(address);
        await sleep(backoff);
      }
    }
    if (!authed) {
      L.warn('SIWE login failed for this key: aborted');
      return;
    }
  } else {
    L.info('✅ session ok');
    if (POST_SESSION_DELAY_MS > 0) { L.debug(`⏳ post-session delay ${POST_SESSION_DELAY_MS}ms...`); await sleep(POST_SESSION_DELAY_MS); }
  }

  if (FLOW_VISIT) { await postEventFast(http, VISIT_EVENT_T, VISIT_EVENT_P); }

  const ctx = {
    http,
    wallet,
    address,
    config: CFG,
    api: API,
    env: { NEURA_RPC, SEPOLIA_RPC, PRIVY_BASE, NEURAVERSE_ORIGIN, DOMAIN, CHAIN_ID_NUM, PRIVY_APP_ID, PRIVY_CA_ID },
    sessionFile: SESSION_FILE,
    logLevel: LOG_LEVEL,
    debug: LOG_LEVEL==='debug',
    fresh: FRESH,
  };

  await faucetClaim(http, address).catch(()=>{});

  await tryRunModule('task',   ctx);
  await tryRunModule('game',   ctx);
  await tryRunModule('bridge', ctx);
  await tryRunModule('swap',   ctx);

  deleteSessionTree(address);
}

// ===== main loop =====
let CURRENT_ADDR = null;
process.on('SIGINT', () => {
  if (CURRENT_ADDR) { deleteSessionTree(CURRENT_ADDR); console.log(`\n[abort] Session ${redact(CURRENT_ADDR,6)} cleaned (Ctrl+C)`); }
  process.exit(130);
});
process.on('SIGTERM', () => {
  if (CURRENT_ADDR) { deleteSessionTree(CURRENT_ADDR); console.log(`\n[abort] Session ${redact(CURRENT_ADDR,6)} cleaned (SIGTERM)`); }
  process.exit(143);
});

(async ()=>{
  try {
    const keys    = getPrivateKeys();
    const proxies = getProxies();
    if (LOG_LEVEL!=='silent') console.log(`Found ${keys.length} private key(s) and ${proxies.length} proxy entry(ies).`);

    let idx = 1;
    for (const pk of keys) {
      const proxy = proxies.length ? proxies[(idx-1) % proxies.length] : (PROXY || SOCKS_PROXY || HTTPS_PROXY || '');
      const addr  = (()=>{ try { return (new ethers.Wallet(pk)).address; } catch { return '(invalid)'; }})();
      CURRENT_ADDR = addr;
      await runForAccount(pk, idx, proxy);
      CURRENT_ADDR = null;
      if (idx < keys.length) await sleep(BETWEEN_ACCOUNTS_MS);
      idx++;
    }
  } catch (e) {
    console.error('[fatal]', e.response?.status || '', e.response?.data ?? e.stack ?? e.message);
    process.exit(1);
  }
})();
