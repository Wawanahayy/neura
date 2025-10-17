#!/usr/bin/env node
// auth-core.mjs — SIWE + Trustline (strict minimal EIP-4361) + memoized trustline

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
const redact = (t,k=12)=>(!t||t.length<=k*2)?t:`${t.slice(0,k)}…${t.slice(-k)}`;
const dump = (o)=>JSON.stringify(o,null,2);

function makeAgents(proxyUrl){
  if(!proxyUrl) return {};
  try{
    const p=String(proxyUrl).trim().toLowerCase();
    if(p.startsWith('socks')){const a=new SocksProxyAgent(proxyUrl);return{httpAgent:a,httpsAgent:a};}
    if(p.startsWith('http')) {const a=new HttpsProxyAgent(proxyUrl);return{httpAgent:a,httpsAgent:a};}
  }catch{}
  return {};
}
function requireEnv(keys){ for(const k of keys) if(!process.env[k]) throw new Error(`[ENV] ${k} is required`); }

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
async function generateTrustlineToken(){
  const cached = _trustlineCache.get('device-token');
  if (cached && (Date.now() - cached.ts) < 60_000) return cached.token;
  if (_genInFlight) return _genInFlight;

  _genInFlight = (async () => {
    try{
      const { stdout } = await execFileAsync('node', ['index.js'], { timeout: 40000 });
      const m = stdout.match(/0\.[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+){1,3}/);
      if(!m) throw new Error('token not found in index.js output');
      const token = m[0].trim();
      console.log('[auth-core] 🎫 trustline token OK:', redact(token));
      _trustlineCache.set('device-token', { token, ts: Date.now() });
      return token;
    }catch(e){
      console.log('[auth-core] ⚠️ gagal generate token dari index.js:', e.message);
      return '';
    }finally{
      _genInFlight = null;
    }
  })();

  return _genInFlight;
}

async function siweFlowOnce({ pk, base, proxyUrl, timeoutMs, baseHeaders }){
  const wallet = new ethers.Wallet(pk);
  const address = wallet.address;
  console.log(`\n[auth-core] ==== LOGIN ${address} ====`);
  if (proxyUrl) console.log('[auth-core] proxy:', proxyUrl);

  const http = axios.create({
    ...makeAgents(proxyUrl),
    baseURL: base,
    timeout: timeoutMs,
    headers: baseHeaders,
    withCredentials: true,
    proxy: false,
    validateStatus: ()=>true
  });

  const deviceToken = await generateTrustlineToken();

  const initBody = deviceToken ? { address, token: deviceToken } : { address };
  console.log('[auth-core] → /siwe/init payload:', dump(initBody));
  const r1 = await http.post('/api/v1/siwe/init', initBody);
  console.log('[auth-core] ← /siwe/init', r1.status, dump(r1.data));
  if(r1.status>=400) throw new Error(`siwe.init ${r1.status}`);
  const nonce = r1.data?.nonce || ethers.hexlify(ethers.randomBytes(8)).slice(2);

  const message = buildSiweMsg({
    domain: process.env.DOMAIN,
    uri: process.env.NEURAVERSE_ORIGIN,
    address,
    chainId: process.env.CHAIN_ID_NUM,
    statement: process.env.SIWE_STATEMENT || undefined
  }).replace('$NONCE', nonce).replace('$ISSUED_AT', new Date().toISOString());

  const signature = await wallet.signMessage(message);
  console.log('[auth-core] SIWE message:\n' + message);
  console.log('[auth-core] signature:', signature);

  // STEP 4: authenticate (CAIP2 → fallback numeric)
  let payload = {
    message,
    signature,
    chainId: `eip155:${process.env.CHAIN_ID_NUM}`,
    walletClientType:'rabby_wallet',
    connectorType:'injected',
    mode:'login-or-sign-up'
  };
  console.log('[auth-core] → /siwe/authenticate payload:', dump(payload));
  let r2 = await http.post('/api/v1/siwe/authenticate', payload);
  if (r2.status >= 400) {
    payload = { ...payload, chainId: Number(process.env.CHAIN_ID_NUM) };
    console.log('[auth-core] ⚙️ retry authenticate (numeric chainId)');
    r2 = await http.post('/api/v1/siwe/authenticate', payload);
  }
  console.log('[auth-core] ← /siwe/authenticate', r2.status, dump(r2.data));
  if (r2.status >= 400) throw new Error(`siwe.authenticate ${r2.status}: ${r2.data?.error || ''}`);

  const data = r2.data || {};
  const bearer = data.identity_token || data.privy_access_token || data.token;
  const setCookies = r2.headers?.['set-cookie'] || [];
  console.log('[auth-core] bearer:', redact(bearer));
  if (setCookies.length) console.log('[auth-core] cookies:', setCookies);
  if(!bearer) throw new Error('login ok tapi tidak ada bearer');

  return { address, bearer, data, cookies: setCookies, wallet };
}

// ===== Public API =====
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
  return siweFlowOnce({ pk, base, proxyUrl, timeoutMs, baseHeaders });
}

export async function forEachAccount({ keys, proxies=[], cb }){
  if(!keys?.length) throw new Error('keys required');
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
  const PRIVY_BASE = process.env.PRIVY_BASE;

  for(let i=0;i<keys.length;i++){
    const pk = keys[i];
    const proxy = proxies.length ? proxies[i%proxies.length] : null;
    try{
      const login = await siweFlowOnce({ pk, base:PRIVY_BASE, proxyUrl:proxy, timeoutMs:20000, baseHeaders });
      console.log(`✅login account ${i+1}/${keys.length}: ${login.address}`);
      await cb({ ...login, proxy });
    }catch(e){
      console.log(`⚠️ akun#${i+1} error:`, e.message);
    }
  }
}

export function getAuth(ctx){
  const { http, address } = ctx || {};
  if(!http?.defaults?.headers?.common?.authorization) throw new Error('bearer missing');
  if(!address) throw new Error('address missing');
  return { http, address };
}

export default { getAuth, getPrivateKeys, getProxies, siweLogin, forEachAccount };
