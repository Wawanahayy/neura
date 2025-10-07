#!/usr/bin/env node
import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import axios from 'axios';
import YAML from 'yaml';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { Wallet, Contract, Interface, JsonRpcProvider, getAddress, hexlify, randomBytes, parseUnits, parseEther, formatEther } = require('ethers');

const REQ_VARS = ['PRIVY_BASE','NEURAVERSE_ORIGIN','DOMAIN','CHAIN_ID_NUM','PRIVY_APP_ID','PRIVY_CA_ID','SEPOLIA_RPC'];
for (const k of REQ_VARS) { if (!process.env[k]) { console.error(`[ENV] ${k} is required`); process.exit(1); } }

const {
  PRIVY_BASE,
  NEURAVERSE_ORIGIN,
  DOMAIN,
  CHAIN_ID_NUM,
  PRIVY_APP_ID,
  PRIVY_CA_ID,
  DEBUG: ENV_DEBUG,
  SAFE_LOG_SECRETS = '1',
  PRIVATE_KEY,
  PRIVATE_KEYS_FILE,
  PROXIES_FILE,
  PROXY,
  SOCKS_PROXY,
  HTTPS_PROXY,
  SEPOLIA_RPC
} = process.env;

const ARGV = new Set(process.argv.slice(2));
const DEBUG = ENV_DEBUG === '1' || ARGV.has('debug');
const FRESH = ARGV.has('fresh');

let CURRENT_PK = null;
let CURRENT_ADDR = null;

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
const FLOW_WHOAMI        = Boolean(get(CFG,'flow.whoami', true));
const FLOW_VISIT         = Boolean(get(CFG,'flow.visit', true));
const POST_LOGIN_DELAY   = Number(get(CFG,'flow.postLoginDelayMs', 0));
const POST_SESSION_DELAY = Number(get(CFG,'flow.postSessionDelayMs', 0));

const BR = get(CFG,'bridge',{});
const BR_TOKEN_ADDR = String(get(BR,'token.address',''));
const BR_TOKEN_DEC  = Number(get(BR,'token.decimals',18));
const BR_SPENDER    = String(get(BR,'spender',''));
const BR_AMOUNT     = String(get(BR,'amount','0'));
const BR_RECIPIENT  = String(get(BR,'recipient','$OWNER'));
const BR_WAIT       = Boolean(get(BR,'waitForReceipt',true));
const BR_CONFS      = Number(get(BR,'confirmations',1));
const BR_USE_TRANSFER = Boolean(get(BR,'useTransfer',false));
const BR_TX         = get(BR,'tx',null);
const BR_GAS_LIMIT  = get(BR,'gasLimit', null);
const BR_ON_REVERT  = String(get(BR,'onRevert','skip')).toLowerCase();
const DRY_RUN       = Boolean(get(BR,'dryRun', false));

const baseInfra = get(API,'endpoints.infraBase','');
const paths = {
  account: get(API,'endpoints.accountPath','/api/account'),
  events:  get(API,'endpoints.eventsPath','/api/events')
};

const SESS_ROOT = path.resolve(ROOT, 'sessions');
fs.mkdirSync(SESS_ROOT, { recursive: true });
const accountDir  = (addr) => path.join(SESS_ROOT, addr.toLowerCase());
const sessionFile = (addr) => path.join(accountDir(addr), 'session.json');
function ensureAccountDir(addr){ fs.mkdirSync(accountDir(addr), { recursive: true }); }
function deleteSessionTree(addr){ try { fs.rmSync(accountDir(addr), { recursive: true, force: true }); } catch {} }

function get(obj, pathStr, def){ try { return pathStr.split('.').reduce((o,k)=> (o && k in o) ? o[k] : undefined, obj) ?? def; } catch { return def; } }
const sleep = (ms)=> new Promise(r=>setTimeout(r,ms));
const redact = (t, keep=6)=>(!t || typeof t!=='string' || t.length<=keep*2) ? t : `${t.slice(0,keep)}…${t.slice(-keep)}`;
function maskProxyForDisplay(proxyUrl){ if (!proxyUrl) return 'no-proxy'; try { const u = new URL(proxyUrl); return (u.protocol||'').replace(':','').toLowerCase()||'proxy'; } catch { const l=String(proxyUrl).toLowerCase(); return l.startsWith('socks')?l.split(':')[0]:(l.startsWith('http')?l.split(':')[0]:'proxy'); } }
function createAgentFromProxy(proxyUrl){ if (!proxyUrl) return { httpAgent:undefined, httpsAgent:undefined }; const p=String(proxyUrl).trim().toLowerCase(); if (p.startsWith('socks')) { const agent=new SocksProxyAgent(proxyUrl); return { httpAgent:agent, httpsAgent:agent }; } const agent=new HttpsProxyAgent(proxyUrl); return { httpAgent:agent, httpsAgent:agent }; }

function compactLine({ method, url, status, ms, data, headers, tag='' }) {
  const ctype = (headers?.['content-type'] || '').toLowerCase();
  const isHtml = s => !!s && typeof s==='string' && (s.trimStart().startsWith('<!DOCTYPE') || s.includes('BAILOUT_TO_CLIENT_SIDE_RENDERING'));
  const preview = (d) => {
    if (LOG_ELIDE_HTML && (ctype.includes('text/html') || isHtml(d))) return '[HTML omitted]';
    if (d && typeof d==='object') { const pick={}; if ('status' in d) pick.status=d.status; if ('message' in d) pick.message=d.message; try { const s=JSON.stringify(Object.keys(pick).length?pick:d); return s.length>LOG_MAX_BODY_CHARS?s.slice(0,LOG_MAX_BODY_CHARS)+'…':s; } catch {} }
    if (typeof d==='string') return d.length>LOG_MAX_BODY_CHARS?d.slice(0,LOG_MAX_BODY_CHARS)+'…':d;
    return String(d ?? '');
  };
  const m=(method||'REQ').toUpperCase();
  const s=status?` ${status}`:'';
  const t=typeof ms==='number'?` (${ms}ms)`:'';
  return `${tag?tag+' ':''}${m} ${url}${s}${t} → ${preview(data)}`;
}

function axiosWithRetry({ origin, proxyUrl }) {
  const agent = createAgentFromProxy(proxyUrl);
  const inst = axios.create({
    timeout: HTTP_TIMEOUT,
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      origin,
      referer: `${origin}/`,
      'privy-app-id': PRIVY_APP_ID,
      'privy-ca-id':  PRIVY_CA_ID,
      'privy-client': 'react-auth:2.25.0',
      'user-agent': 'Mozilla/5.0 (CLI Privy Bot)'
    },
    withCredentials: true,
    httpAgent: agent.httpAgent,
    httpsAgent: agent.httpsAgent,
    proxy: false,
    validateStatus: () => true
  });

  inst.interceptors.request.use(cfg=>{ cfg.meta={ start:Date.now() }; return cfg; });

  inst.interceptors.response.use(async res=>{
    const s=res.status, cfg=res.config||{}; const retriable = s===429 || (s>=500 && s<600);
    if (retriable && (cfg.__retryCount||0) < NET_RETRIES) {
      cfg.__retryCount=(cfg.__retryCount||0)+1;
      const delay=Math.floor(NET_BASE_DELAY*Math.pow(NET_BACKOFF,cfg.__retryCount-1)+Math.random()*NET_JITTER);
      if (LOG_LEVEL!=='silent') console.log(`network retry ${cfg.__retryCount}/${NET_RETRIES} in ${delay}ms → ${cfg.url} (status ${s})`);
      await sleep(delay);
      return inst(cfg);
    }
    return res;
  }, async err=>{
    const cfg=err.config||{}; const retriableCode=new Set(['ECONNABORTED','ECONNRESET','ETIMEDOUT','EAI_AGAIN','ECONNREFUSED','EPIPE']);
    if ((cfg.__retryCount||0) < NET_RETRIES && (retriableCode.has(err.code) || /socket hang up/i.test(err.message||''))) {
      cfg.__retryCount=(cfg.__retryCount||0)+1;
      const delay=Math.floor(NET_BASE_DELAY*Math.pow(NET_BACKOFF,cfg.__retryCount-1)+Math.random()*NET_JITTER);
      if (LOG_LEVEL!=='silent') console.log(`network retry ${cfg.__retryCount}/${NET_RETRIES} in ${delay}ms → ${cfg.url} (${err.code||err.message})`);
      await sleep(delay);
      return inst(cfg);
    }
    return Promise.reject(err);
  });

  if (DEBUG || LOG_LEVEL==='debug') {
    inst.interceptors.request.use(cfg=>{
      let auth=cfg.headers?.authorization; let cookie=cfg.headers?.Cookie||cfg.headers?.cookie;
      if (SAFE_LOG_SECRETS==='1') { if (auth) auth=`Bearer ${redact(String(auth).replace(/^Bearer\s+/i,'').trim())}`; if (cookie) cookie='(set)'; }
      const headers = LOG_SHOW_HEADERS ? { origin:cfg.headers?.origin,'privy-app-id':cfg.headers?.['privy-app-id'],authorization:auth,Cookie:cookie } : undefined;
      const proxyDisp = maskProxyForDisplay(proxyUrl);
      console.log(compactLine({ method:cfg.method, url:cfg.url, data:cfg.data, headers, tag:`⇢ [proxy=${proxyDisp}]` }));
      return cfg;
    });
    inst.interceptors.response.use(res=>{
      const ms=Date.now()-(res.config.meta?.start||Date.now());
      const headers = LOG_SHOW_HEADERS ? res.headers : undefined;
      const proxyDisp = maskProxyForDisplay(proxyUrl);
      console.log(compactLine({ method:res.config.method, url:res.config.url, status:res.status, ms, data:res.data, headers, tag:`⇠ [proxy=${proxyDisp}]` }));
      return res;
    }, err=>{
      const cfg=err.config||{}; const ms=Date.now()-(cfg.meta?.start||Date.now());
      const headers = LOG_SHOW_HEADERS ? err.response?.headers : undefined;
      const proxyDisp = maskProxyForDisplay(proxyUrl);
      console.log(compactLine({ method:cfg.method, url:cfg.url, status:err.response?.status, ms, data:err.response?.data, headers, tag:`⇠ [proxy=${proxyDisp}]` }));
      return Promise.reject(err);
    });
  }

  return inst;
}

async function withRetries(attempts, fn, label) {
  let lastErr;
  for (let i=0;i<attempts;i++){
    try { return await fn(); } catch(e){
      lastErr=e;
      const delay=Math.floor(NET_BASE_DELAY*Math.pow(NET_BACKOFF,i)+Math.random()*NET_JITTER);
      console.log(`${label} failed (${i+1}/${attempts}) → ${e.code || e.response?.status || e.message}; retrying in ${delay}ms`);
      await sleep(delay);
    }
  }
  throw lastErr;
}

function checksumFlexible(addr) {
  const s = String(addr || '');
  if (!/^0x[0-9a-fA-F]{40}$/.test(s)) throw new Error('invalid address format');
  try { return getAddress(s); } catch { return getAddress(s.toLowerCase()); }
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
  const payload = { message, signature, chainId: `eip155:${CHAIN_ID_NUM}`, walletClientType:'rabby_wallet', connectorType:'injected', mode:'login-or-sign-up' };
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
  if (res.status === 401 || res.status === 403) res = await doPost(true);
  if (res.status >= 400) throw new Error(`siwe.authenticate status ${res.status}`);
  const setCookies = res.headers?.['set-cookie'] || [];
  const bag = {};
  for (const sc of setCookies) { const m = String(sc).match(/^([^=]+)=([^;]+)/); if (m) bag[m[1]] = m[2]; }
  return { data: res.data, cookieBag: bag };
}

async function apiAccount(http) {
  const res = await http.get(`${baseInfra}${paths.account}`);
  if (res.status>=400) throw new Error(`api.account ${res.status}`);
  return res.data;
}
async function postEvent(http, type, payload={}) { try { await http.post(`${baseInfra}${paths.events}`, { type, payload }); } catch {} }

function setAuthHeadersFromSession(http, sess){
  const bearer = sess?.id_token || sess?.bearer || sess?.access_token || sess?.privy_token;
  if (bearer) http.defaults.headers.common['authorization'] = `Bearer ${bearer}`; else delete http.defaults.headers.common['authorization'];
  const cookies = [];
  if (sess?.id_token)       cookies.push(`privy-id-token=${sess.id_token}`);
  if (sess?.access_token)   cookies.push(`privy-access-token=${sess.access_token}`);
  if (sess?.privy_token)    cookies.push(`privy-token=${sess.privy_token}`);
  if (sess?.refresh_token)  cookies.push(`privy-refresh-token=${sess.refresh_token}`);
  if (sess?.session)        cookies.push(`privy-session=${sess.session}`);
  if (cookies.length) http.defaults.headers.common['Cookie'] = cookies.join('; '); else delete http.defaults.headers.common['Cookie'];
  if (DEBUG || LOG_LEVEL==='debug') {
    const show = SAFE_LOG_SECRETS==='1'
      ? { bearer: redact(bearer||''), cookies: cookies.length ? '(set)' : '(none)' }
      : { bearer, cookies: cookies.join('; ') || '(none)' };
    console.log('[dbg] session.set', show);
  }
}

const ERC20_ABI = [
  'function balanceOf(address) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
  'function allowance(address owner, address spender) view returns (uint256)',
  'function approve(address spender, uint256 value) returns (bool)',
  'function transfer(address to, uint256 value) returns (bool)'
];

async function ensureAllowance(provider, tokenAddr, owner, spender, wantAmount, wait, confs) {
  const signer = new Wallet(CURRENT_PK, provider);
  const erc20  = new Contract(tokenAddr, ERC20_ABI, signer);
  const current = await erc20.allowance(owner, spender);
  if (current >= wantAmount) return;
  console.log(`[allowance] not enough → approving ${wantAmount.toString()} for ${spender}`);
  if (DRY_RUN) { console.log('[dry-run] skip approve'); return; }
  const tx = await erc20.approve(spender, wantAmount);
  console.log(`[approve] tx: ${tx.hash}`);
  if (wait) {
    const r = await tx.wait(Math.max(0, Number(confs)));
    console.log(`[approve] confirmed in block ${r.blockNumber}`);
  }
}

async function performBridge(provider, tokenAddr, amount, opts) {
  const signer = new Wallet(CURRENT_PK, provider);
  const token  = new Contract(tokenAddr, ERC20_ABI, signer);
  const [balNative, balToken] = await Promise.all([ provider.getBalance(CURRENT_ADDR), token.balanceOf(CURRENT_ADDR) ]);
  console.log(`[balance] native=${formatEther(balNative)} | token=${balToken.toString()}`);

  if (BR_TX && BR_TX.to && BR_TX.abi && BR_TX.method) {
    const to = checksumFlexible(BR_TX.to);
    const iface = new Interface(BR_TX.abi);
    const recipient = (!BR_RECIPIENT || BR_RECIPIENT==='$OWNER') ? CURRENT_ADDR : checksumFlexible(BR_RECIPIENT);
    const vars = { TOKEN: tokenAddr, AMOUNT: amount, OWNER: CURRENT_ADDR, RECIPIENT: recipient };
    const args = Array.isArray(BR_TX.args) ? BR_TX.args.map(a => (typeof a!=='string') ? a : (a==='$TOKEN'?vars.TOKEN:(a==='$AMOUNT'?vars.AMOUNT:(a==='$OWNER'?vars.OWNER:(a==='$RECIPIENT'?vars.RECIPIENT:a))))) : [];
    const data = iface.encodeFunctionData(BR_TX.method, args);
    const value = BR_TX.value ? parseEther(String(BR_TX.value)) : 0n;
    console.log(`[bridge] mode=CUSTOM → to=${to}, method=${BR_TX.method}, value=${value}`);
    if (DRY_RUN) { console.log('[dry-run] skip sendTransaction'); return true; }
    try {
      const tx = await signer.sendTransaction({ to, data, value, ...(BR_GAS_LIMIT?{gasLimit: BigInt(BR_GAS_LIMIT)}:{}) });
      console.log(`[tx] ${tx.hash}`);
      if (opts.wait) {
        const r = await tx.wait(Math.max(0, Number(opts.confs)));
        console.log(`[tx] confirmed in block ${r.blockNumber}`);
      }
      return true;
    } catch (e) {
      console.log(`[bridge-error] custom tx failed → ${e.reason || e.message || e.code || 'unknown'}`);
      return false;
    }
  }

  if (BR_USE_TRANSFER) {
    const to = checksumFlexible(BR_SPENDER);
    console.log(`[bridge] mode=TRANSFER → to=${to}, amount=${amount.toString()}`);
    if (DRY_RUN) { console.log('[dry-run] skip transfer'); return true; }
    try {
      const tx = await token.transfer(to, amount, ...(BR_GAS_LIMIT?[{gasLimit: BigInt(BR_GAS_LIMIT)}]:[]));
      console.log(`[tx] ${tx.hash}`);
      if (opts.wait) {
        const r = await tx.wait(Math.max(0, Number(opts.confs)));
        console.log(`[tx] confirmed in block ${r.blockNumber}`);
      }
      return true;
    } catch (e) {
      console.log(`[bridge-error] transfer failed → ${e.reason || e.message || e.code || 'unknown'}`);
      return false;
    }
  }

  const bridgeTo = checksumFlexible(BR_SPENDER);
  const iface = new Interface(['function deposit(uint256 _amount, address _recipient)']);
  const recipient = (!BR_RECIPIENT || BR_RECIPIENT==='$OWNER') ? CURRENT_ADDR : checksumFlexible(BR_RECIPIENT);
  const data = iface.encodeFunctionData('deposit', [amount, recipient]);
  console.log(`[bridge] mode=DEPOSIT → to=${bridgeTo}, amount=${amount.toString()}, recipient=${recipient}`);
  if (DRY_RUN) { console.log('[dry-run] skip deposit'); return true; }
  try {
    const tx = await signer.sendTransaction({ to: bridgeTo, data, value: 0n, ...(BR_GAS_LIMIT?{gasLimit: BigInt(BR_GAS_LIMIT)}:{}) });
    console.log(`[tx] ${tx.hash}`);
    if (opts.wait) {
      const r = await tx.wait(Math.max(0, Number(opts.confs)));
      console.log(`[tx] confirmed in block ${r.blockNumber}`);
    }
    return true;
  } catch (e) {
    console.log(`[bridge-error] deposit failed → ${e.reason || e.message || e.code || 'unknown'}`);
    return false;
  }
}

async function runForAccount(pk, index, proxyForThisAccount) {
  CURRENT_PK = pk;
  const wallet = new Wallet(pk);
  CURRENT_ADDR = wallet.address;
  const safeProxy = maskProxyForDisplay(proxyForThisAccount);

  ensureAccountDir(CURRENT_ADDR);
  const SESSION_FILE = sessionFile(CURRENT_ADDR);
  const http = axiosWithRetry({ origin: NEURAVERSE_ORIGIN, proxyUrl: proxyForThisAccount });

  function loadSession(){ if (FRESH) return {}; try { return JSON.parse(fs.readFileSync(SESSION_FILE,'utf8')); } catch { return {}; } }
  function saveSession(s){ ensureAccountDir(CURRENT_ADDR); fs.writeFileSync(SESSION_FILE, JSON.stringify(s,null,2)); setAuthHeadersFromSession(http,s); }

  const sess0 = loadSession();
  setAuthHeadersFromSession(http, sess0);

  console.log(`\n== Account #${index} (${redact(CURRENT_ADDR,6)}) | proxy=${safeProxy} ==`);
  if (FLOW_WHOAMI) {
    console.log(`Address: ${CURRENT_ADDR}`);
    console.log(`Networks: Sepolia`);
  }

  if (!BR_TOKEN_ADDR) { console.log('bridge.token.address missing → skip'); deleteSessionTree(CURRENT_ADDR); return; }
  if (!BR_AMOUNT || Number(BR_AMOUNT) <= 0) { console.log('bridge.amount must be > 0 → skip'); deleteSessionTree(CURRENT_ADDR); return; }
  if (!BR_USE_TRANSFER && !BR_TX && !BR_SPENDER) { console.log('bridge.spender required (deposit mode) → skip'); deleteSessionTree(CURRENT_ADDR); return; }

  let sessionValid = false;
  try { await apiAccount(http); sessionValid = true; } catch {}
  if (!sessionValid || FRESH) {
    let lastErr;
    for (let i=0;i<LOGIN_TRIES;i++){
      try {
        const init = await siweInit(http, CURRENT_ADDR).catch(async e=>{
          if (e.response?.status===401 || e.response?.status===403) return await siweInit(http, CURRENT_ADDR, { cleanHeaders:true });
          throw e;
        });
        const nonce = init?.nonce || hexlify(randomBytes(16)).slice(2);
        const message = buildSiweMessage({
          domain: DOMAIN, uri: NEURAVERSE_ORIGIN, address: CURRENT_ADDR,
          statement: 'By signing, you are proving you own this wallet and logging in.',
          nonce, chainId: CHAIN_ID_NUM, issuedAt: new Date().toISOString()
        });
        const signature = await wallet.signMessage(message);
        const { data: authData, cookieBag } = await siweAuthenticate(http, { message, signature });
        const session = {};
        if (authData?.identity_token)     session.id_token = authData.identity_token;
        if (authData?.privy_access_token) session.access_token = authData.privy_access_token;
        if (authData?.token)              session.privy_token = authData.token;
        if (authData?.refresh_token && authData.refresh_token !== 'deprecated') session.refresh_token = authData.refresh_token;
        if (cookieBag['privy-id-token'])      session.id_token = cookieBag['privy-id-token'];
        if (cookieBag['privy-access-token'])  session.access_token = cookieBag['privy-access-token'];
        if (cookieBag['privy-token'])         session.privy_token = cookieBag['privy-token'];
        if (cookieBag['privy-refresh-token']) session.refresh_token = cookieBag['privy-refresh-token'];
        if (cookieBag['privy-session'])       session.session = cookieBag['privy-session'];
        session.bearer = session.id_token || session.access_token || session.privy_token;
        if (!session.bearer) throw new Error('Login ok but no token');
        saveSession(session);
        await apiAccount(http);
        console.log('✅ login ok');
        if (POST_LOGIN_DELAY > 0) { console.log(`⏳ post-login delay ${POST_LOGIN_DELAY}ms...`); await sleep(POST_LOGIN_DELAY); }
        break;
      } catch(e){
        lastErr=e;
        const delay=Math.floor(NET_BASE_DELAY*Math.pow(NET_BACKOFF,i)+Math.random()*NET_JITTER);
        console.log(`Login failed (${i+1}/${LOGIN_TRIES}) → ${e.code || e.response?.status || e.message}; retrying in ${delay}ms`);
        await sleep(delay);
      }
    }
    if (!sessionValid && lastErr) { console.log('[login-error]', lastErr.message || lastErr.code || 'unknown'); deleteSessionTree(CURRENT_ADDR); return; }
  } else {
    console.log('✅ session ok');
    if (POST_SESSION_DELAY > 0) { console.log(`⏳ post-session delay ${POST_SESSION_DELAY}ms...`); await sleep(POST_SESSION_DELAY); }
  }

  if (FLOW_VISIT) {
    const evType = get(CFG,'bridge.visitEvent.type', get(CFG,'visitEvent.type','bridge:visit'));
    const evPayload = get(CFG,'bridge.visitEvent.payload', get(CFG,'visitEvent.payload',{}));
    await postEvent(http, evType, evPayload);
  }

  const provider = new JsonRpcProvider(SEPOLIA_RPC);
  const tokenAddr = checksumFlexible(BR_TOKEN_ADDR);
  const want      = parseUnits(BR_AMOUNT, BR_TOKEN_DEC);

  if (!BR_USE_TRANSFER && !BR_TX) {
    try {
      const spender = checksumFlexible(BR_SPENDER);
      await ensureAllowance(provider, tokenAddr, CURRENT_ADDR, spender, want, BR_WAIT, BR_CONFS);
    } catch (e) {
      console.log(`[approve-error] ${e.reason || e.message || e.code || 'unknown'} → skip`);
      deleteSessionTree(CURRENT_ADDR);
      return;
    }
  }

  let ok = await performBridge(provider, tokenAddr, want, { wait: BR_WAIT, confs: BR_CONFS });
  if (!ok && BR_ON_REVERT === 'transfer') {
    try {
      const signer = new Wallet(CURRENT_PK, provider);
      const token  = new Contract(tokenAddr, ERC20_ABI, signer);
      const to = checksumFlexible(BR_SPENDER);
      console.log(`[fallback] deposit failed → trying TRANSFER to ${to} amount=${want.toString()}`);
      if (!DRY_RUN) {
        const tx = await token.transfer(to, want, ...(BR_GAS_LIMIT?[{gasLimit: BigInt(BR_GAS_LIMIT)}]:[]));
        console.log(`[tx] ${tx.hash}`);
        if (BR_WAIT) {
          const r = await tx.wait(Math.max(0, Number(BR_CONFS)));
          console.log(`[tx] confirmed in block ${r.blockNumber}`);
        }
      } else {
        console.log('[dry-run] skip fallback transfer');
      }
    } catch (e) {
      console.log(`[fallback-error] ${e.reason || e.message || e.code || 'unknown'} → skip`);
    }
  }

  deleteSessionTree(CURRENT_ADDR);
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

const BETWEEN_ACCOUNTS_MS = 5000;

process.on('SIGINT', () => { if (CURRENT_ADDR) { deleteSessionTree(CURRENT_ADDR); console.log(`\n[abort] Session ${redact(CURRENT_ADDR,6)} cleaned (Ctrl+C)`); } process.exit(130); });
process.on('SIGTERM', () => { if (CURRENT_ADDR) { deleteSessionTree(CURRENT_ADDR); console.log(`\n[abort] Session ${redact(CURRENT_ADDR,6)} cleaned (SIGTERM)`); } process.exit(143); });

(async ()=>{
  try {
    const keys = getPrivateKeys();
    const proxies = getProxies();
    let idx = 1;
    for (const pk of keys) {
      const proxy = proxies.length ? proxies[(idx-1) % proxies.length] : (PROXY || SOCKS_PROXY || HTTPS_PROXY || '');
      await runForAccount(pk, idx, proxy);
      if (idx < keys.length) await sleep(BETWEEN_ACCOUNTS_MS);
      idx++;
    }
  } catch (e) {
    console.error('[fatal]', e.response?.status || '', e.response?.data ?? e.stack ?? e.message);
    process.exit(1);
  }
})();
