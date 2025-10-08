#!/usr/bin/env node
import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import axios from 'axios';
import { ethers } from 'ethers';
import YAML from 'yaml';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';

const REQ_VARS = ['NEURA_RPC','PRIVY_BASE','NEURAVERSE_ORIGIN','DOMAIN','CHAIN_ID_NUM','PRIVY_APP_ID','PRIVY_CA_ID'];
for (const k of REQ_VARS) { if (!process.env[k]) { console.error(`[ENV] ${k} is required`); process.exit(1); } }

const {
  NEURA_RPC,
  PRIVY_BASE,
  NEURAVERSE_ORIGIN,
  DOMAIN,
  CHAIN_ID_NUM,
  PRIVY_APP_ID,
  PRIVY_CA_ID,
  DEBUG: ENV_DEBUG,
  SAFE_LOG_SECRETS = '1',
  SEPOLIA_RPC,
  TOKEN_CONTRACT,
  PRIVATE_KEY,
  PRIVATE_KEYS_FILE,
  PROXIES_FILE,
  PROXY,
  SOCKS_PROXY,
  HTTPS_PROXY,
} = process.env;

const ARGV = new Set(process.argv.slice(2));
const DEBUG = ENV_DEBUG === '1' || ARGV.has('debug');
const FRESH = ARGV.has('fresh');

const ROOT = process.cwd();
const CONFIG_YAML = path.resolve(ROOT, 'config.yaml');
const API_JSON    = path.resolve(ROOT, 'api.json');
if (!fs.existsSync(CONFIG_YAML)) { console.error('Missing config.yaml'); process.exit(1); }
if (!fs.existsSync(API_JSON)) { console.error('Missing api.json'); process.exit(1); }
const CFG = YAML.parse(fs.readFileSync(CONFIG_YAML,'utf8'));
const API = JSON.parse(fs.readFileSync(API_JSON,'utf8'));

const HTTP_TIMEOUT   = Number(get(CFG,'net.timeoutMs', 45000));
const NET_RETRIES    = Number(get(CFG,'net.retries', 4));
const NET_BASE_DELAY = Number(get(CFG,'net.baseDelayMs', 900));
const NET_BACKOFF    = Number(get(CFG,'net.backoff', 1.8));
const NET_JITTER     = Number(get(CFG,'net.jitterMs', 350));
const LOGIN_TRIES    = Number(get(CFG,'login.tries', 3));

const LOG_LEVEL          = String(get(CFG,'log.level','info'));
const LOG_MAX_BODY_CHARS = Number(get(CFG,'log.maxBodyChars',180));
const LOG_ELIDE_HTML     = Boolean(get(CFG,'log.elideHtml',true));
const LOG_SHOW_HEADERS   = Boolean(get(CFG,'log.showHeaders',false));

const FLOW_WHOAMI   = Boolean(get(CFG,'flow.whoami', true));
const FLOW_VISIT    = Boolean(get(CFG,'flow.visit', true));
const VISIT_EVENT_T = String(get(CFG,'visitEvent.type','game:visitValidatorHouse'));
const VISIT_EVENT_P = get(CFG,'visitEvent.payload', {});
const POST_LOGIN_DELAY_MS   = Number(get(CFG,'flow.postLoginDelayMs', 0));
const POST_SESSION_DELAY_MS = Number(get(CFG,'flow.postSessionDelayMs', 0));

const CLAIM_SKIP_BELOW    = Boolean(get(CFG,'claim.skipIfBelowPoints', false));
const CLAIM_MIN_POINTS    = Number(get(CFG,'claim.minPoints', 0));
const CLAIM_RETRY_FOREVER = Boolean(get(CFG,'claim.retryForever', false));
const CLAIM_ATTEMPTS      = Number(get(CFG,'claim.attempts', 25));
const CLAIM_FACTOR        = Number(get(CFG,'claim.factor', 1.6));
const CLAIM_JITTER        = Number(get(CFG,'claim.jitterMs', 800));
const CLAIM_SPAM          = Number(get(CFG,'claim.spam', 1));
const CLAIM_INTERVAL      = Number(get(CFG,'claim.intervalMs', 2500));
const CLAIM_STOP_ON       = (get(CFG,'claim.stopOn', []) || []).map(s=>String(s||'').toLowerCase());

const SESS_ROOT = path.resolve(ROOT, 'sessions');
fs.mkdirSync(SESS_ROOT, { recursive: true });
const accountDir  = (addr) => path.join(SESS_ROOT, addr.toLowerCase());
const sessionFile = (addr) => path.join(accountDir(addr), 'session.json');
function ensureAccountDir(addr){ fs.mkdirSync(accountDir(addr), { recursive: true }); }
function deleteSessionTree(addr){ try { fs.rmSync(accountDir(addr), { recursive: true, force: true }); } catch {} }

function get(obj, pathStr, def) { try { return pathStr.split('.').reduce((o,k)=> (o && k in o) ? o[k] : undefined, obj) ?? def; } catch { return def; } }
const sleep  = (ms)=> new Promise(r=>setTimeout(r,ms));
const redact = (t, keep=6) => (!t || typeof t!=='string' || t.length<=keep*2) ? t : `${t.slice(0,keep)}…${t.slice(-keep)}`;

function compactLine({ method, url, status, ms, data, headers, tag='', maxBodyChars=180, elideHtml=true }) {
  const previewBody = (data, headers) => {
    const ctype = (headers?.['content-type'] || '').toLowerCase();
    const isHtmlLike = s => !!s && typeof s==='string' && (s.trimStart().startsWith('<!DOCTYPE') || s.includes('BAILOUT_TO_CLIENT_SIDE_RENDERING'));
    if (elideHtml && (ctype.includes('text/html') || isHtmlLike(data))) return `[HTML omitted]`;
    if (data && typeof data === 'object') {
      const pick = {};
      if ('status' in data) pick.status = data.status;
      if ('message' in data) pick.message = data.message;
      try { const s = JSON.stringify(Object.keys(pick).length ? pick : data); return s.length>maxBodyChars ? s.slice(0,maxBodyChars)+'…' : s; } catch {}
    }
    if (typeof data==='string') return data.length>maxBodyChars?data.slice(0,maxBodyChars)+'…':data;
    return String(data ?? '');
  };
  const m = (method||'REQ').toUpperCase();
  const s = status ? ` ${status}` : '';
  const t = typeof ms==='number' ? ` (${ms}ms)` : '';
  return `${tag?tag+' ':''}${m} ${url}${s}${t} → ${previewBody(data, headers)}`;
}

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

  instance.interceptors.request.use(cfg=>{ cfg.meta = { start: Date.now() }; return cfg; });

  instance.interceptors.response.use(async res=>{
    const s = res.status;
    const retriable = s===429 || (s>=500 && s<600);
    const cfg = res.config || {};
    if (retriable && (cfg.__retryCount||0) < NET_RETRIES) {
      cfg.__retryCount = (cfg.__retryCount||0) + 1;
      const delay = Math.floor(NET_BASE_DELAY * Math.pow(NET_BACKOFF, cfg.__retryCount - 1) + Math.random()*NET_JITTER);
      if (LOG_LEVEL !== 'silent') console.log(`network retry ${cfg.__retryCount}/${NET_RETRIES} in ${delay}ms → ${cfg.url} (status ${s})`);
      await sleep(delay);
      return instance(cfg);
    }
    return res;
  }, async err=>{
    const cfg = err.config || {};
    const retriableCode = new Set(['ECONNABORTED','ECONNRESET','ETIMEDOUT','EAI_AGAIN','ECONNREFUSED','EPIPE']);
    if ((cfg.__retryCount||0) < NET_RETRIES && (retriableCode.has(err.code) || /socket hang up/i.test(err.message||''))) {
      cfg.__retryCount = (cfg.__retryCount||0) + 1;
      const delay = Math.floor(NET_BASE_DELAY * Math.pow(NET_BACKOFF, cfg.__retryCount - 1) + Math.random()*NET_JITTER);
      if (LOG_LEVEL !== 'silent') console.log(`network retry ${cfg.__retryCount}/${NET_RETRIES} in ${delay}ms → ${cfg.url} (${err.code||err.message})`);
      await sleep(delay);
      return instance(cfg);
    }
    return Promise.reject(err);
  });

  if (DEBUG || LOG_LEVEL === 'debug') {
    instance.interceptors.request.use(cfg=>{
      let auth = cfg.headers?.authorization;
      let cookie = cfg.headers?.Cookie || cfg.headers?.cookie;
      if (SAFE_LOG_SECRETS === '1') {
        if (auth)  auth  = `Bearer ${redact(String(auth).replace(/^Bearer\s+/i,'').trim())}`;
        if (cookie) cookie = '(set)';
      }
      const headers = LOG_SHOW_HEADERS ? {
        origin: cfg.headers?.origin,
        'privy-app-id': cfg.headers?.['privy-app-id'],
        authorization: auth,
        Cookie: cookie,
      } : undefined;
      const proxyDisp = maskProxyForDisplay(proxyUrl);
      console.log(compactLine({
        method: cfg.method, url: cfg.url, data: cfg.data, headers,
        tag:`⇢ [proxy=${proxyDisp}]`, maxBodyChars: LOG_MAX_BODY_CHARS, elideHtml: LOG_ELIDE_HTML
      }));
      return cfg;
    });
    instance.interceptors.response.use(res=>{
      const ms = Date.now() - (res.config.meta?.start || Date.now());
      const headers = LOG_SHOW_HEADERS ? res.headers : undefined;
      const proxyDisp = maskProxyForDisplay(proxyUrl);
      console.log(compactLine({
        method: res.config.method, url: res.config.url, status: res.status, ms,
        data: res.data, headers, tag:`⇠ [proxy=${proxyDisp}]`,
        maxBodyChars: LOG_MAX_BODY_CHARS, elideHtml: LOG_ELIDE_HTML
      }));
      return res;
    }, err=>{
      const cfg = err.config || {};
      const ms = Date.now() - (cfg.meta?.start || Date.now());
      const headers = LOG_SHOW_HEADERS ? err.response?.headers : undefined;
      const proxyDisp = maskProxyForDisplay(proxyUrl);
      console.log(compactLine({
        method: cfg.method, url: cfg.url, status: err.response?.status, ms,
        data: err.response?.data, headers, tag:`⇠ [proxy=${proxyDisp}]`,
        maxBodyChars: LOG_MAX_BODY_CHARS, elideHtml: LOG_ELIDE_HTML
      }));
      return Promise.reject(err);
    });
  }

  return instance;
}

async function withRetries(attempts, fn, label) {
  let lastErr;
  for (let i=0;i<attempts;i++) {
    try { return await fn(); } catch (e) {
      lastErr = e;
      const delay = Math.floor(NET_BASE_DELAY * Math.pow(NET_BACKOFF, i) + Math.random()*NET_JITTER);
      console.log(`${label} failed (${i+1}/${attempts}) → ${e.code || e.response?.status || e.message}; retrying in ${delay}ms`);
      await sleep(delay);
    }
  }
  throw lastErr;
}

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
async function siweInit(http, addr, { cleanHeaders=false } = {}) {
  const url = `${PRIVY_BASE}/api/v1/siwe/init`;
  if (cleanHeaders) {
    const { authorization, Cookie, ...rest } = http.defaults.headers.common;
    const tmp = axios.create({ ...http.defaults, headers: rest, timeout: HTTP_TIMEOUT, proxy: false, validateStatus: () => true });
    if (http.defaults.httpsAgent) tmp.defaults.httpsAgent = http.defaults.httpsAgent;
    if (http.defaults.httpAgent)  tmp.defaults.httpAgent  = http.defaults.httpAgent;
    const res = await tmp.post(url, { address: addr });
    if (res.status >= 400) throw new Error(`siwe.init status ${res.status}`);
    return res.data;
  }
  const res = await http.post(url, { address: addr });
  if (res.status >= 400) throw new Error(`siwe.init status ${res.status}`);
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
  const doPost = async (strip=false) => {
    if (strip) {
      const { authorization, Cookie, ...rest } = http.defaults.headers.common;
      const tmp = axios.create({ ...http.defaults, headers: rest, timeout: HTTP_TIMEOUT, proxy: false, validateStatus: () => true });
      if (http.defaults.httpsAgent) tmp.defaults.httpsAgent = http.defaults.httpsAgent;
      if (http.defaults.httpAgent)  tmp.defaults.httpAgent  = http.defaults.httpAgent;
      return await tmp.post(url, payload);
    }
    return await http.post(url, payload);
  };
  let res = await doPost(false);
  if (res.status === 401 || res.status === 403) {
    console.log('Re-auth with stripped headers');
    res = await doPost(true);
  }
  if (res.status >= 400) throw new Error(`siwe.authenticate status ${res.status}`);
  const setCookies = res.headers?.['set-cookie'] || [];
  const bag = {};
  for (const sc of setCookies) { const m = String(sc).match(/^([^=]+)=([^;]+)/); if (m) bag[m[1]] = m[2]; }
  return { data: res.data, cookieBag: bag };
}

const baseApp   = get(API,'endpoints.appBase','');
const baseInfra = get(API,'endpoints.infraBase','');
const paths = {
  account: get(API,'endpoints.accountPath','/api/account'),
  events:  get(API,'endpoints.eventsPath','/api/events'),
  faucet:  '/api/faucet',
  leaderboards: get(API,'endpoints.leaderboardsPath','/api/leaderboards'),
  tasks: get(API,'endpoints.tasksPath','/api/tasks'),
  claimPaths: get(API,'endpoints.claimPaths',[]),
};

async function apiAccount(http) { const res = await http.get(`${baseInfra}${paths.account}`); if (res.status>=400) throw new Error(`api.account ${res.status}`); return res.data; }
async function apiLeaderboards(http) { const res = await http.get(`${baseInfra}${paths.leaderboards}`); if (res.status>=400) throw new Error(`api.leaderboards ${res.status}`); return res.data; }
async function apiTasks(http) { const res = await http.get(`${baseInfra}${paths.tasks}`); if (res.status>=400) throw new Error(`api.tasks ${res.status}`); return res.data; }
async function postEvent(http, type, payload={}) { try { await http.post(`${baseInfra}${paths.events}`, { type, payload }); } catch {} }

function accountPoints(acc){
  if (!acc || typeof acc!=='object') return null;
  if (typeof acc.points === 'number') return acc.points;
  if (typeof acc.total_points === 'number') return acc.total_points;
  if (typeof acc.score === 'number') return acc.score;
  return null;
}

function buildBodies(to) {
  return (API.claimBodies || []).map(b => {
    if (!b || typeof b !== 'object') return {};
    const s = JSON.stringify(b).replaceAll('$ADDRESS', to);
    return JSON.parse(s);
  });
}
function stopOnMatch(text){
  if (!text) return null;
  const s = String(text).toLowerCase();
  for (const needle of CLAIM_STOP_ON) {
    if (needle && s.includes(needle)) return needle;
  }
  return null;
}
async function claimAt(url, bodies, http){
  let last;
  for (let i=0;i<bodies.length;i++){
    const body = bodies[i];
    const res = await http.post(url, body);
    const status = res.status;
    const data = res.data;
    const text = typeof data==='object' ? (data?.message || data?.status || JSON.stringify(data)) : (data||'');
    const hit = stopOnMatch(text);
    if (status < 400) {
      if (hit) { const e = new Error(`server says stop: ${hit}`); e._stop=true; e._reason=hit; e._raw=text; e._url=url; throw e; }
      return { url, body, data };
    }
    if (hit) { const e = new Error(`server says stop: ${hit}`); e._stop=true; e._reason=hit; e._raw=text; e._url=url; throw e; }
    last = new Error(`HTTP ${status} ${text}`);
  }
  if (last) throw last;
  throw new Error('all bodies failed at ' + url);
}
async function tryClaimOnce(to, http){
  const bodies = buildBodies(to);
  const primary = `${baseApp}${paths.faucet}`;
  const tryUrl = async (u)=>{
    try { return await claimAt(u, bodies, http); }
    catch (e){
      if (e._stop) { e.message = `STOP (${e._reason}) @ ${u} → ${e._raw}`; throw e; }
      return null;
    }
  };
  let out = await tryUrl(primary);
  if (out) return out;
  for (const p of paths.claimPaths){
    out = await tryUrl(`${baseApp}${p}`); if (out) return out;
    out = await tryUrl(`${baseInfra}${p}`); if (out) return out;
  }
  throw new Error('No claim endpoint succeeded');
}
async function claimWithPolicy(to, http){
  const attempts = CLAIM_RETRY_FOREVER ? Number.MAX_SAFE_INTEGER : Math.max(1, CLAIM_ATTEMPTS);
  for (let i=0;i<attempts;i++){
    try {
      const out = await tryClaimOnce(to, http);
      const msg = out?.data?.message || out?.data?.status || JSON.stringify(out?.data||{});
      console.log(`Claim: ${msg}`);
      return out;
    } catch (e) {
      if (e._stop) { console.log(`Claim STOP: ${e.message}`); return { stopped: true, reason: e._reason, raw: e._raw, url: e._url }; }
      const status = e.response?.status;
      const body = e.response?.data;
      const text = typeof body==='object' ? (body?.message || JSON.stringify(body)) : (body || e.message);
      const hit = stopOnMatch(text);
      if (hit) { console.log(`Claim STOP (matched "${hit}") → ${text}`); return { stopped: true, reason: hit, raw: text }; }
      const delay = Math.floor(CLAIM_JITTER + Math.random()*CLAIM_JITTER + Math.pow(CLAIM_FACTOR, i));
      console.log(`Claim failed (${i+1}/${CLAIM_RETRY_FOREVER?'∞':CLAIM_ATTEMPTS}) → ${status || ''} ${text}; retrying in ${delay}ms`);
      await sleep(delay);
    }
  }
  throw new Error('Claim attempts exhausted');
}

const ERC20_ABI_MIN = ['function balanceOf(address) view returns (uint256)','function decimals() view returns (uint8)','function symbol() view returns (string)'];
async function getNativeBalance(rpc, addr) { const provider = new ethers.JsonRpcProvider(rpc); const bal = await provider.getBalance(addr); return ethers.formatEther(bal); }
async function getErc20Balance(rpc, tokenAddr, addr, decimalsHint) {
  const provider = new ethers.JsonRpcProvider(rpc);
  const c = new ethers.Contract(tokenAddr, ERC20_ABI_MIN, provider);
  const [raw, decimals, symbol] = await Promise.all([ c.balanceOf(addr), typeof decimalsHint === 'number' ? decimalsHint : c.decimals(), c.symbol().catch(()=>'TOKEN') ]);
  const d = typeof decimalsHint === 'number' ? decimalsHint : decimals;
  return { symbol, decimals: d, raw: raw.toString(), formatted: ethers.formatUnits(raw, d) };
}

async function runForAccount(pk, index, proxyForThisAccount) {
  const wallet = new ethers.Wallet(pk);
  const address = wallet.address;
  const safeProxy = maskProxyForDisplay(proxyForThisAccount);

  ensureAccountDir(address);
  const SESSION_FILE = sessionFile(address);

  const http = axiosWithRetry({ origin: NEURAVERSE_ORIGIN, proxyUrl: proxyForThisAccount });

  function loadSession(){ if (FRESH) return {}; try { return JSON.parse(fs.readFileSync(SESSION_FILE,'utf8')); } catch { return {}; } }
  function saveSession(s){ ensureAccountDir(address); fs.writeFileSync(SESSION_FILE, JSON.stringify(s,null,2)); setAuthHeadersFromSession(s); }
  function setAuthHeadersFromSession(sess){
    const bearer = sess?.id_token || sess?.bearer || sess?.access_token || sess?.privy_token;
    if (bearer) http.defaults.headers.common['authorization'] = `Bearer ${bearer}`; else delete http.defaults.headers.common['authorization'];
    const cookies = [];
    if (sess?.id_token)       cookies.push(`privy-id-token=${sess.id_token}`);
    if (sess?.access_token)   cookies.push(`privy-access-token=${sess.access_token}`);
    if (sess?.privy_token)    cookies.push(`privy-token=${sess.privy_token}`);
    if (sess?.refresh_token)  cookies.push(`privy-refresh-token=${sess.refresh_token}`);
    if (sess?.session)        cookies.push(`privy-session=${sess.session}`);
    if (cookies.length) http.defaults.headers.common['Cookie'] = cookies.join('; '); else delete http.defaults.headers.common['Cookie'];
    if (DEBUG || LOG_LEVEL === 'debug') {
      const show = SAFE_LOG_SECRETS==='1'
        ? { bearer: redact(bearer||''), cookies: cookies.length ? '(set)' : '(none)' }
        : { bearer, cookies: cookies.join('; ') || '(none)' };
      console.log('[dbg] session.set', show);
    }
  }
  setAuthHeadersFromSession(loadSession());

  console.log(`\n== Account #${index} (${redact(address,6)}) | proxy=${safeProxy} ==`);
  if (FLOW_WHOAMI) {
    console.log(`Address: ${address}`);
    console.log(`Networks: Neura Testnet${SEPOLIA_RPC ? ', Sepolia' : ''}`);
  }

  try {
    let acc = null;
    let sessionValid = false;
    try { acc = await apiAccount(http); sessionValid = true; } catch {}

    if (!sessionValid || FRESH) {
      let lastErr;
      for (let i=0;i<LOGIN_TRIES;i++){
        try {
          const init = await siweInit(http, address).catch(async e=>{
            if (e.response?.status===401 || e.response?.status===403) return await siweInit(http, address,{cleanHeaders:true});
            throw e;
          });
          const nonce = init?.nonce || ethers.hexlify(ethers.randomBytes(16)).slice(2);
          const message = buildSiweMessage({
            domain: DOMAIN, uri: NEURAVERSE_ORIGIN, address,
            statement: 'By signing, you are proving you own this wallet and logging in.',
            nonce, chainId: CHAIN_ID_NUM, issuedAt: new Date().toISOString(),
          });
          const signature = await wallet.signMessage(message);
          const { data: authData, cookieBag } = await siweAuthenticate(http, { message, signature });
          const sess = {};
          if (authData?.identity_token) sess.id_token = authData.identity_token;
          if (authData?.privy_access_token) sess.access_token = authData.privy_access_token;
          if (authData?.token) sess.privy_token = authData.token;
          if (authData?.refresh_token && authData.refresh_token !== 'deprecated') sess.refresh_token = authData.refresh_token;
          if (cookieBag['privy-id-token']) sess.id_token = cookieBag['privy-id-token'];
          if (cookieBag['privy-access-token']) sess.access_token = cookieBag['privy-access-token'];
          if (cookieBag['privy-token']) sess.privy_token = cookieBag['privy-token'];
          if (cookieBag['privy-refresh-token']) sess.refresh_token = cookieBag['privy-refresh-token'];
          if (cookieBag['privy-session']) sess.session = cookieBag['privy-session'];
          sess.bearer = sess.id_token || sess.access_token || sess.privy_token;
          if (!sess.bearer) throw new Error('Login ok but no token');
          saveSession(sess);
          acc = await apiAccount(http);
          console.log('✅ login ok');
          if (POST_LOGIN_DELAY_MS > 0) { console.log(`⏳ post-login delay ${POST_LOGIN_DELAY_MS}ms...`); await sleep(POST_LOGIN_DELAY_MS); }
          break;
        } catch (e) {
          lastErr = e;
          const delay = Math.floor(NET_BASE_DELAY * Math.pow(NET_BACKOFF, i) + Math.random()*NET_JITTER);
          console.log(`Login failed (${i+1}/${LOGIN_TRIES}) → ${e.code || e.response?.status || e.message}; retrying in ${delay}ms`);
          await sleep(delay);
        }
      }
      if (!acc) throw lastErr || new Error('Login failed');
    } else {
      console.log('✅ session ok');
      if (POST_SESSION_DELAY_MS > 0) { console.log(`⏳ post-session delay ${POST_SESSION_DELAY_MS}ms...`); await sleep(POST_SESSION_DELAY_MS); }
    }

    if (FLOW_VISIT) {
      await postEvent(http, VISIT_EVENT_T, VISIT_EVENT_P);
    }

    try {
      const lb = await withRetries(3, async ()=> await apiLeaderboards(http), 'leaderboards');
      console.log('\n🏆 Leaderboard (preview)');
      let top = []; let me = null;
      if (Array.isArray(lb?.top)) { top = lb.top; me = lb.me ?? null; }
      else if (Array.isArray(lb)) { top = lb; }
      else if (Array.isArray(lb?.data)) { top = lb.data; }
      console.log('→ Your rank: not available');
    } catch {
      console.log('\n🏆 Leaderboard (preview)');
      console.log('→ Your rank: not available');
    }

    let stopped = false;

    if (CLAIM_SKIP_BELOW) {
      const pts = accountPoints(acc);
      if (pts !== null && pts < CLAIM_MIN_POINTS) {
        console.log(`Skip claim: points ${pts} < ${CLAIM_MIN_POINTS}`);
        stopped = true;
      }
    }

    if (!stopped) {
      for (let s=0; s<Math.max(1,CLAIM_SPAM); s++){
        const r = await claimWithPolicy(address, http).catch(e => ({ error: e?.message || String(e) }));
        if (r?.stopped) { stopped = true; break; }
        if (s < CLAIM_SPAM-1) await sleep(CLAIM_INTERVAL);
      }
    }

    try {
      const nets = [];
      const neura = (get(CFG,'balances.networks', []) || []).find(n => n.rpcEnv === 'NEURA_RPC');
      if (neura) {
        const tokenAddr = neura?.erc20?.address || TOKEN_CONTRACT || '0xB88Ca91Fef0874828e5ea830402e9089aaE0bB7F';
        nets.push({ name: neura.name || 'Neura Testnet', rpc: NEURA_RPC, nativeSymbol: neura.nativeSymbol || 'ANKR', erc20: { address: tokenAddr, decimals: neura?.erc20?.decimals ?? 18 } });
      }
      if (SEPOLIA_RPC) {
        const sp = get(CFG,'balances.sepoliaToken', null);
        nets.push({ name: 'Sepolia', rpc: SEPOLIA_RPC, nativeSymbol: 'ETH', erc20: sp ? { address: sp.address, decimals: sp.decimals ?? 18 } : null });
      }
      for (const net of nets) {
        try { const native = await getNativeBalance(net.rpc, address); console.log(`Balance ${net.name} ${net.nativeSymbol} = ${native}`); } catch (e2) { console.log(`Balance ${net.name} native failed: ${e2.message}`); }
        if (net.erc20?.address) {
          try { const erc = await getErc20Balance(net.rpc, ethers.getAddress(net.erc20.address), address, net.erc20.decimals); console.log(`Balance ${net.name} ${erc.symbol} = ${erc.formatted}`); }
          catch (e3) { console.log(`Balance ${net.name} ERC20 failed: ${e3.message}`); }
        }
      }
    } catch {}
  } catch (e) {
    console.error(`[account error] ${redact(address,6)} → ${e.code || e.response?.status || e.message}`);
  } finally {
    deleteSessionTree(address);
  }
}

const BETWEEN_ACCOUNTS_MS = 5000;
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
    const keys = getPrivateKeys();
    const proxies = getProxies();
    let idx = 1;
    for (const pk of keys) {
      const proxy = proxies.length ? proxies[(idx-1) % proxies.length] : (PROXY || SOCKS_PROXY || HTTPS_PROXY || '');
      const addr = (new ethers.Wallet(pk)).address;
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