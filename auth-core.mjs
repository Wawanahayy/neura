#!/usr/bin/env node
// auth-core.mjs — SIWE + Trustline, return {address, bearer, cookies[]} siap dipakai header Cookie
// Fitur: retry /siwe/init, normalisasi socks5→socks5h, resume session dari history map/file

import 'dotenv/config';
import axios from 'axios';
import { ethers } from 'ethers';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);

const sleep = (ms)=> new Promise(r=>setTimeout(r,ms));
const redactMid = (t,k=12)=>(!t||t.length<=k*2)?t:`${t.slice(0,k)}…${t.slice(-k)}`;

// ==== normalizer socks5 -> socks5h (DNS lewat proxy) ====
function normalizeProxyUrl(u) {
  if (!u) return u;
  try {
    const url = new URL(u);
    if (url.protocol === 'socks5:') {
      url.protocol = 'socks5h:';            // upgrade agar DNS terjadi di proxy
      return url.toString();
    }
    return u;
  } catch {
    return String(u).startsWith('socks5://')
      ? String(u).replace(/^socks5:\/\//, 'socks5h://')
      : u;
  }
}

function requireEnv(keys){ for(const k of keys) if(!process.env[k]) throw new Error(`[ENV] ${k} is required`); }

function makeAgents(proxyUrl){
  if(!proxyUrl) return {};
  try{
    const raw = normalizeProxyUrl(String(proxyUrl).trim());
    const p=raw.toLowerCase();
    if(p.startsWith('socks')){const a=new SocksProxyAgent(raw);return{httpAgent:a,httpsAgent:a};}
    if(p.startsWith('http')) {const a=new HttpsProxyAgent(raw);return{httpAgent:a,httpsAgent:a};}
  }catch{}
  return {};
}
function parseProxy(proxyUrl) {
  if (!proxyUrl) return { enabled: false };
  try {
    const norm = normalizeProxyUrl(proxyUrl);
    const u = new URL(norm);
    const kind = (u.protocol || '').replace(':','').toLowerCase();
    return { enabled: true, kind, host: u.hostname || '', port: u.port || '', user: u.username || '', pass: u.password || '', raw: norm };
  } catch {
    const raw = normalizeProxyUrl(String(proxyUrl));
    const low = raw.toLowerCase();
    const kind = low.startsWith('socks') ? (low.startsWith('socks5h') ? 'socks5h' : 'socks5')
                : (low.startsWith('https') ? 'https'
                : (low.startsWith('http') ? 'http' : 'proxy'));
    return { enabled: true, kind, host: raw, port: '', user: '', pass: '', raw };
  }
}
function logSocket(proxyUrl, socketLevel='off') {
  const level = String(socketLevel||'off').toLowerCase();
  const p = parseProxy(proxyUrl);
  if (!p.enabled) { console.log('proxy ❗️off❗️'); return; }
  if (level === 'off') { console.log('proxy ON ✅'); return; }
  if (level === 'on')  { console.log(`✅ ${(p.kind||'proxy').toUpperCase()} ON ✅`); return; }
  const auth = (p.user || p.pass) ? `${p.user}:${p.pass}@` : '';
  const hp   = `${p.host}${p.port ? ':'+p.port : ''}`;
  console.log(`✅ ${(p.kind||'proxy').toUpperCase()} ${auth}${hp} ✅`);
}

function makeLogger({ logLevel='silent' } = {}) {
  const level = String(logLevel||'silent').toLowerCase();
  const isSilent   = level === 'silent';
  const isDbgApi   = level === 'debugapi';
  const isDbgAll   = level === 'debugall';
  const show = !isSilent;
  return {
    level,
    mini:  (...a)=> console.log(...a),
    info:  (...a)=> show && console.log(...a),
    warn:  (...a)=> console.warn(...a),
    error: (...a)=> console.error(...a),
    api:   (...a)=> (isDbgApi || isDbgAll) && console.log(...a),
    all:   (...a)=> isDbgAll && console.log(...a),
    redactIfNeeded: (s)=> (isDbgAll ? s : redactMid(s)),
  };
}

function compactPreview(data) {
  const max = 180;
  if (data && typeof data==='object') {
    try {
      const pick={}; if ('status' in data) pick.status=data.status; if ('message' in data) pick.message=data.message;
      const s = JSON.stringify(Object.keys(pick).length?pick:data);
      return s.length>max ? s.slice(0,max)+'…' : s;
    } catch {}
  }
  if (typeof data==='string') return data.length>max ? data.slice(0,max)+'…' : data;
  return String(data ?? '');
}

function buildSiweMsg({ domain, uri, address, chainId, statement }){
  return `${domain} wants you to sign in with your Ethereum account:
${address}

${statement || 'By signing, you are proving you own this wallet and logging in.'}

URI: ${uri}
Version: 1
Chain ID: ${Number(chainId)}
Nonce: $NONCE
Issued At: $ISSUED_AT`;
}

const _trustlineCache = new Map();
let _genInFlight = null;
async function generateTrustlineToken(log){
  const cached = _trustlineCache.get('device-token');
  if (cached && (Date.now() - cached.ts) < 60_000) return cached.token;
  if (_genInFlight) return _genInFlight;

  _genInFlight = (async () => {
    try{
      const { stdout } = await execFileAsync('node', ['index.js'], { timeout: 40000 });
      const m = stdout.match(/0\.[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+){1,3}/);
      if(!m) throw new Error('token not found in index.js output');
      const token = m[0].trim();
      log.info('[auth-core] 🎫 trustline token OK:', log.redactIfNeeded(token));
      _trustlineCache.set('device-token', { token, ts: Date.now() });
      return token;
    }catch(e){
      log.warn('[auth-core] ⚠️ gagal generate token dari index.js:', e.message);
      return '';
    }finally{
      _genInFlight = null;
    }
  })();

  return _genInFlight;
}

function toCookieArray(setCookieHeader) {
  const arr = Array.isArray(setCookieHeader) ? setCookieHeader : (setCookieHeader ? [setCookieHeader] : []);
  return arr.map(s => String(s).split(';')[0].trim()).filter(Boolean);
}

// === helper: robust POST dengan rate-limit & WAF handling untuk /siwe/init ===
async function initSiweWithRetry({ http, address, deviceToken, log }) {
  const tries     = Math.max(1, Number(process.env.SIWE_INIT_TRIES   || 6));
  const baseDelay = Math.max(0, Number(process.env.SIWE_INIT_BASE_MS || 800));
  const backoff   = Math.max(1, Number(process.env.SIWE_INIT_BACKOFF || 2.0));
  const jitter    = Math.max(0, Number(process.env.SIWE_INIT_JITTER  || 400));

  // 2 pola payload: {address, token} → {address} fallback
  const payloads = deviceToken
    ? [ { address, token: deviceToken }, { address } ]
    : [ { address } ];

  let lastErr;
  let delay = baseDelay;

  for (let t = 1; t <= tries; t++) {
    for (let p = 0; p < payloads.length; p++) {
      try {
        const r = await http.post('/api/v1/siwe/init', payloads[p]);
        // Sukses
        if (r.status >= 200 && r.status < 300 && (r.data?.nonce || r.status === 200)) return r;

        // Rate limited → hormati Retry-After
        if (r.status === 429) {
          const ra = r.headers?.['retry-after'];
          let waitMs = 0;
          if (ra) {
            const asNum = parseInt(String(ra), 10);
            if (!Number.isNaN(asNum)) {
              waitMs = asNum * 1000;
            } else {
              const ts = Date.parse(String(ra));
              if (!Number.isNaN(ts)) waitMs = Math.max(0, ts - Date.now());
            }
          }
          const jitterMs = Math.floor(Math.random()*jitter);
          const backoffMs = Math.max(waitMs, delay) + jitterMs;
          log.info(`auth retry ${t}/${tries} (payload#${p+1}) → 429; sleep ${backoffMs}ms`);
          await sleep(backoffMs);
          delay = Math.floor(delay * backoff);
          continue;
        }

        // 401/403/503 bisa transient (WAF/CDN, sesi buntu, atau token tidak diakui)
        if (r.status === 401 || r.status === 403 || r.status === 503) {
          const jitterMs = Math.floor(Math.random()*jitter);
          const backoffMs = delay + jitterMs;
          log.info(`auth retry ${t}/${tries} (payload#${p+1}) → ${r.status}; sleep ${backoffMs}ms`);
          await sleep(backoffMs);
          delay = Math.floor(delay * backoff);
          continue;
        }

        // Error lain → simpan terakhir dan coba payload/iterasi lain
        lastErr = new Error(`siwe.init ${r.status}`);
      } catch (e) {
        // Network/timeout → backoff lalu ulang
        const msg = e?.message || String(e);
        const isTimeout = /timeout/i.test(msg) || e?.code === 'ECONNABORTED';
        const isTransient = isTimeout || /ECONNRESET|ENETUNREACH|EAI_AGAIN|ETIMEDOUT/i.test(msg)
                          || /before secure TLS connection/i.test(msg);
        if (!isTransient) throw e;
        const jitterMs = Math.floor(Math.random()*jitter);
        const backoffMs = delay + jitterMs;
        log.info(`auth retry ${t}/${tries} (payload#${p+1}) → transient; sleep ${backoffMs}ms`);
        await sleep(backoffMs);
        delay = Math.floor(delay * backoff);
      }
    }
  }
  throw lastErr || new Error('siwe.init failed after retries');
}

/* ===== HTTP helper utk validasi session ===== */
function makeNeuraApiHttp({ base, proxyUrl, timeoutMs }) {
  const baseURL = base || process.env.NEURA_API_BASE || 'https://neuraverse.neuraprotocol.io';
  return axios.create({
    ...makeAgents(proxyUrl),
    baseURL,
    timeout: timeoutMs || 20000,
    withCredentials: true,
    proxy: false,
    validateStatus: ()=>true
  });
}

async function tryResumeFromHistory({ history, proxyUrl, timeoutMs, log }) {
  if (!history || !history.bearer || !Array.isArray(history.cookies) || !history.cookies.length) {
    return { ok:false, reason:'missing_fields' };
  }
  const httpMain = makeNeuraApiHttp({ base: 'https://neuraverse.neuraprotocol.io', proxyUrl, timeoutMs });
  const httpInfra = makeNeuraApiHttp({ base: process.env.NEURA_API_BASE || 'https://neuraverse-testnet.infra.neuraprotocol.io', proxyUrl, timeoutMs });

  const headers = {
    accept:'application/json',
    'content-type':'application/json',
    origin:process.env.NEURAVERSE_ORIGIN,
    referer:`${process.env.NEURAVERSE_ORIGIN || ''}/`,
    authorization:`Bearer ${history.bearer}`,
    Cookie: history.cookies.map(String).join('; ')
  };

  const tests = [
    { http: httpInfra, url:'/api/account', desc:'infra/account' },
    { http: httpMain , url:'/api/tasks'  , desc:'main/tasks'   },
  ];

  for (const t of tests) {
    try {
      const r = await t.http.get(t.url, { headers });
      if (r.status === 200) {
        log?.mini?.(`[session] resume OK via ${t.desc}`);
        return { ok:true, bearer: history.bearer, cookies: history.cookies };
      }
    } catch {}
  }
  return { ok:false, reason:'validate_failed' };
}

function loadHistoryForAddress(filePath, address) {
  try {
    if (!filePath || !fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath, 'utf8');
    const map = JSON.parse(raw);            // { "0xaddr": { bearer, cookies[] }, ... }
    const key = String(address||'').toLowerCase();
    const hit = map[key];
    if (!hit) return null;
    if (!Array.isArray(hit.cookies)) return null;
    return { address: key, bearer: hit.bearer, cookies: hit.cookies };
  } catch { return null; }
}

/* ===== SIWE flow utama ===== */
async function siweFlowOnce({ pk, base, proxyUrl, timeoutMs, baseHeaders, logLevel='silent', socketLevel='off' }){
  const log = makeLogger({ logLevel });
  const wallet = new ethers.Wallet(pk);
  const address = wallet.address;

  log.mini(`[auth-core] LOGIN ${address}`);
  logSocket(proxyUrl, socketLevel);

  const http = axios.create({
    ...makeAgents(proxyUrl),
    baseURL: base,
    timeout: timeoutMs,
    headers: baseHeaders,
    withCredentials: true,
    proxy: false,
    validateStatus: ()=>true
  });

  if (log.level !== 'silent') {
    http.interceptors.request.use(cfg=>{
      cfg.meta = { start: Date.now() };
      log.api(`⇢ ${String(cfg.method||'POST').toUpperCase()} ${cfg.baseURL || ''}${cfg.url} → ${compactPreview(cfg.data)}`);
      return cfg;
    });
    http.interceptors.response.use(res=>{
      const ms = Date.now() - (res.config.meta?.start || Date.now());
      log.api(`⇠ ${String(res.config.method||'POST').toUpperCase()} ${res.config.baseURL || ''}${res.config.url} ${res.status} (${ms}ms) → ${compactPreview(res.data)}`);
      return res;
    });
  }

  const deviceToken = await generateTrustlineToken(log);

  // init + retry
  const r1 = await initSiweWithRetry({ http, address, deviceToken, log });
  const nonce = r1.data?.nonce || ethers.hexlify(ethers.randomBytes(8)).slice(2);

  const message = buildSiweMsg({
    domain: process.env.DOMAIN,
    uri: process.env.NEURAVERSE_ORIGIN,
    address,
    chainId: process.env.CHAIN_ID_NUM,
    statement: process.env.SIWE_STATEMENT || undefined
  }).replace('$NONCE', nonce).replace('$ISSUED_AT', new Date().toISOString());

  const signature = await wallet.signMessage(message);
  log.mini('[auth-core] sign OK');

  // authenticate dengan fallback chainId numeric
  const tries = Math.max(1, Number(process.env.SIWE_AUTH_TRIES || 2));
  const baseDelay = Math.max(0, Number(process.env.SIWE_AUTH_BASE_MS || 800));
  const backoff   = Math.max(1, Number(process.env.SIWE_AUTH_BACKOFF || 1.8));
  const jitter    = Math.max(0, Number(process.env.SIWE_AUTH_JITTER || 250));

  let payload = {
    message, signature,
    chainId: `eip155:${process.env.CHAIN_ID_NUM}`,
    walletClientType:'rabby_wallet',
    connectorType:'injected',
    mode:'login-or-sign-up'
  };

  let lastErr;
  let delayAuth = baseDelay;
  for (let t=1; t<=tries; t++){
    try {
      let r2 = await http.post('/api/v1/siwe/authenticate', payload);
      if (r2.status >= 400) {
        payload = { ...payload, chainId: Number(process.env.CHAIN_ID_NUM) };
        r2 = await http.post('/api/v1/siwe/authenticate', payload);
      }
      if (r2.status >= 400) throw new Error(`siwe.authenticate ${r2.status}: ${r2.data?.error || ''}`);

      const data = r2.data || {};
      const bearer = data.identity_token || data.privy_access_token || data.token;
      const setCookies = toCookieArray(r2.headers?.['set-cookie']);
      if(!bearer) throw new Error('login ok tapi tidak ada bearer');
      return { address, bearer, data, cookies: setCookies, wallet };
    } catch (e) {
      lastErr = e;
      const msg = e?.message || String(e);
      const isTimeout = /timeout/i.test(msg) || e?.code === 'ECONNABORTED';
      const isTransient = isTimeout || /ECONNRESET|ENETUNREACH|EAI_AGAIN|ETIMEDOUT/i.test(msg);
      if (t === tries || !isTransient) throw e;
      const jitterMs = Math.floor(Math.random()*jitter);
      await sleep(delayAuth + jitterMs);
      delayAuth = Math.floor(delayAuth*backoff);
    }
  }
  throw lastErr || new Error('authenticate failed');
}

/* ===== Public helpers ===== */
export function getPrivateKeys(){
  const { PRIVATE_KEYS_FILE, PRIVATE_KEY } = process.env;
  if(PRIVATE_KEYS_FILE && fs.existsSync(PRIVATE_KEYS_FILE)){
    const lines=fs.readFileSync(PRIVATE_KEYS_FILE,'utf8').split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
    if(lines.length) return lines;
  }
  if(PRIVATE_KEY) return [PRIVATE_KEY.trim()];
  throw new Error('No PRIVATE_KEY or PRIVATE_KEYS_FILE');
}

export function getProxies(){
  const { PROXIES_FILE, PROXY, SOCKS_PROXY, HTTPS_PROXY } = process.env;
  if(PROXIES_FILE && fs.existsSync(PROXIES_FILE)){
    return fs.readFileSync(PROXIES_FILE,'utf8')
      .split(/\r?\n/)
      .map(s=>s.trim())
      .filter(Boolean)
      .map(normalizeProxyUrl); 
  }
  const envSingle = PROXY || SOCKS_PROXY || HTTPS_PROXY || '';
  return envSingle ? [normalizeProxyUrl(envSingle)] : [];
}

export async function siweLogin(pk, opts={}){
  requireEnv(['PRIVY_BASE','NEURAVERSE_ORIGIN','DOMAIN','CHAIN_ID_NUM','PRIVY_APP_ID','PRIVY_CA_ID']);
  const baseHeaders = {
    accept:'application/json',
    'content-type':'application/json',
    origin:process.env.NEURAVERSE_ORIGIN,
    referer:`${process.env.NEURAVERSE_ORIGIN}/`,
    'privy-app-id':process.env.PRIVY_APP_ID,
    'privy-ca-id':process.env.PRIVY_CA_ID,
    'privy-client':'react-auth:2.25.0',
    'user-agent':'Mozilla/5.0 (CLI Privy Bot)',
  };
  const base = process.env.PRIVY_BASE;
  const proxyUrl = opts.proxyUrl || '';
  const timeoutMs = Number(process.env.SIWE_TIMEOUT_MS || 20000);
  const logLevel = opts.logLevel || 'silent';
  const socketLevel = opts.socketLevel || 'off';
  const log = makeLogger({ logLevel });

  // 🔁 Resume dari history map/file (alamat → {bearer,cookies[]})
  const wallet = new ethers.Wallet(pk);
  const addrLower = wallet.address.toLowerCase();
  let history = null;

  if (opts.historyMap) {
    const hit = opts.historyMap[addrLower];
    if (hit && Array.isArray(hit.cookies)) history = { address: addrLower, bearer: hit.bearer, cookies: hit.cookies };
  }
  if (!history && opts.historyMapFile) {
    history = loadHistoryForAddress(opts.historyMapFile, addrLower);
  }

  if (history && history.bearer && history.cookies?.length) {
    const resume = await tryResumeFromHistory({ history, proxyUrl, timeoutMs, log });
    if (resume.ok) {
      return { address: wallet.address, bearer: resume.bearer, data: { resumed:true }, cookies: resume.cookies, wallet };
    } else {
      log.info?.(`[session] histori untuk ${wallet.address} tidak valid (${resume.reason}), lanjut SIWE.`);
    }
  }

  // 🔐 fallback: SIWE normal
  return siweFlowOnce({ pk, base, proxyUrl, timeoutMs, baseHeaders, logLevel, socketLevel });
}

export function getAuth(ctx){
  const { http, address } = ctx || {};
  if(!http?.defaults?.headers?.common?.authorization) throw new Error('bearer missing');
  if(!address) throw new Error('address missing');
  return { http, address };
}

export default { getAuth, getPrivateKeys, getProxies, siweLogin };
