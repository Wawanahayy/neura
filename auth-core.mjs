#!/usr/bin/env node
// auth-core.mjs — SIWE + Trustline, return {address, bearer, cookies[]} siap dipakai header Cookie

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

function requireEnv(keys){ for(const k of keys) if(!process.env[k]) throw new Error(`[ENV] ${k} is required`); }

function makeAgents(proxyUrl){
  if(!proxyUrl) return {};
  try{
    const p=String(proxyUrl).trim().toLowerCase();
    if(p.startsWith('socks')){const a=new SocksProxyAgent(proxyUrl);return{httpAgent:a,httpsAgent:a};}
    if(p.startsWith('http')) {const a=new HttpsProxyAgent(proxyUrl);return{httpAgent:a,httpsAgent:a};}
  }catch{}
  return {};
}
function parseProxy(proxyUrl) {
  if (!proxyUrl) return { enabled: false };
  try {
    const u = new URL(proxyUrl);
    const kind = (u.protocol || '').replace(':','').toLowerCase();
    return { enabled: true, kind, host: u.hostname || '', port: u.port || '', user: u.username || '', pass: u.password || '', raw: proxyUrl };
  } catch {
    const low = String(proxyUrl).toLowerCase();
    const kind = low.startsWith('socks') ? 'socks5'
                : (low.startsWith('https') ? 'https'
                : (low.startsWith('http') ? 'http' : 'proxy'));
    return { enabled: true, kind, host: proxyUrl, port: '', user: '', pass: '', raw: proxyUrl };
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

  const initBody = deviceToken ? { address, token: deviceToken } : { address };
  const r1 = await http.post('/api/v1/siwe/init', initBody);
  if (r1.status>=400) throw new Error(`siwe.init ${r1.status}`);
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
  let delay = baseDelay;
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
      await sleep(delay + jitterMs);
      delay = Math.floor(delay*backoff);
    }
  }
  throw lastErr || new Error('authenticate failed');
}

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
    return fs.readFileSync(PROXIES_FILE,'utf8').split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
  }
  const envSingle = PROXY || SOCKS_PROXY || HTTPS_PROXY || '';
  return envSingle ? [envSingle] : [];
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
  return siweFlowOnce({ pk, base, proxyUrl, timeoutMs, baseHeaders, logLevel, socketLevel });
}

export function getAuth(ctx){
  const { http, address } = ctx || {};
  if(!http?.defaults?.headers?.common?.authorization) throw new Error('bearer missing');
  if(!address) throw new Error('address missing');
  return { http, address };
}

export default { getAuth, getPrivateKeys, getProxies, siweLogin };
