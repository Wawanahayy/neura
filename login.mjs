// auth-core.mjs — core helpers (SIWE login, loop akun, utils)
// Kompatibel: import { getAuth } from './auth-core.mjs'
//             import core from './auth-core.mjs'

import 'dotenv/config';
import axios from 'axios';
import { ethers } from 'ethers';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';
import fs from 'node:fs';

// ===== Utils =====
const sleep = (ms)=> new Promise(r=>setTimeout(r,ms));
const redact = (t,k=6)=> (!t||t.length<=k*2) ? t : `${t.slice(0,k)}…${t.slice(-k)}`;
const bool = (x)=> !!x;

function makeAgents(proxyUrl){
  if (!proxyUrl) return {};
  try {
    const p = String(proxyUrl).trim().toLowerCase();
    if (p.startsWith('socks')) { const a=new SocksProxyAgent(proxyUrl); return { httpAgent:a, httpsAgent:a }; }
    if (p.startsWith('http'))  { const a=new HttpsProxyAgent(proxyUrl); return { httpAgent:a, httpsAgent:a }; }
  } catch {}
  return {};
}

function buildSiweMsg({ domain, uri, address, chainId, statement }){
  return `${domain} wants you to sign in with your Ethereum account:
${address}

${statement || 'By signing, you are proving you own this wallet and logging in.'}

URI: ${uri}
Version: 1
Chain ID: ${chainId}
Nonce: $NONCE
Issued At: $ISSUED_AT
Resources:
- https://privy.io`;
}

function requireEnv(keys){
  for (const k of keys) if (!process.env[k]) throw new Error(`[ENV] ${k} is required`);
}

// ===== Public: getPrivateKeys / getProxies =====
export function getPrivateKeys(){
  const { PRIVATE_KEYS_FILE, PRIVATE_KEY } = process.env;
  if (PRIVATE_KEYS_FILE && fs.existsSync(PRIVATE_KEYS_FILE)) {
    const lines = fs.readFileSync(PRIVATE_KEYS_FILE,'utf8')
      .split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
    if (lines.length) return lines;
  }
  if (PRIVATE_KEY) return [PRIVATE_KEY.trim()];
  throw new Error('No private key found. Set PRIVATE_KEYS_FILE or PRIVATE_KEY in .env');
}

export function getProxies(){
  const { PROXIES_FILE, PROXY, SOCKS_PROXY, HTTPS_PROXY } = process.env;
  if (PROXIES_FILE && fs.existsSync(PROXIES_FILE)) {
    return fs.readFileSync(PROXIES_FILE,'utf8')
      .split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
  }
  const envSingle = PROXY || SOCKS_PROXY || HTTPS_PROXY || '';
  return envSingle ? [envSingle] : [];
}

// ===== SIWE flow (robust) =====
async function siweFlowOnce({ pk, base, proxyUrl, timeoutMs, baseHeaders }) {
  let wallet;
  try { wallet = new ethers.Wallet(pk); }
  catch (e) { throw new Error(`Invalid PRIVATE_KEY: ${e.message}`); }
  const address = wallet.address;

  const http = axios.create({
    ...makeAgents(proxyUrl),
    baseURL: base,
    timeout: timeoutMs,
    headers: baseHeaders,
    withCredentials: true,
    proxy: false,
    validateStatus: ()=>true
  });

  // INIT
  const r1 = await http.post('/api/v1/siwe/init', { address });
  if (r1.status >= 400) throw new Error(`siwe.init ${r1.status}`);
  const nonce = r1.data?.nonce || ethers.hexlify(ethers.randomBytes(16)).slice(2);

  // MESSAGE & SIGN
  const msgTpl = buildSiweMsg({
    domain: process.env.DOMAIN,
    uri: process.env.NEURAVERSE_ORIGIN,
    address,
    chainId: process.env.CHAIN_ID_NUM
  });
  const message = msgTpl.replace('$NONCE', nonce).replace('$ISSUED_AT', new Date().toISOString());
  const signature = await wallet.signMessage(message);

  // AUTH
  const payload = {
    message, signature,
    chainId: `eip155:${process.env.CHAIN_ID_NUM}`,
    walletClientType:'rabby_wallet',
    connectorType:'injected',
    mode:'login-or-sign-up'
  };
  let r2 = await http.post('/api/v1/siwe/authenticate', payload);

  // clean retry for 401/403
  if (r2.status === 401 || r2.status === 403) {
    const clean = axios.create({
      ...makeAgents(proxyUrl),
      baseURL: base,
      timeout: timeoutMs,
      headers: baseHeaders,
      withCredentials: true,
      proxy: false,
      validateStatus: ()=>true
    });
    r2 = await clean.post('/api/v1/siwe/authenticate', payload);
  }
  if (r2.status >= 400) throw new Error(`siwe.authenticate ${r2.status}`);

  // cookies + bearer
  const setCookies = r2.headers?.['set-cookie'] || [];
  const bag = {};
  for (const sc of setCookies) {
    const m = String(sc).match(/^([^=]+)=([^;]+)/);
    if (m) bag[m[1]] = m[2];
  }
  const authData = r2.data || {};
  const bearer = authData.identity_token || authData.privy_access_token || authData.token
              || bag['privy-id-token'] || bag['privy-access-token'] || bag['privy-token'];
  if (!bearer) throw new Error('login ok tapi tidak ada bearer');

  return {
    address,
    bearer,
    tokens: {
      id_token: authData.identity_token || bag['privy-id-token'] || null,
      access_token: authData.privy_access_token || bag['privy-access-token'] || null,
      privy_token: authData.token || bag['privy-token'] || null,
    },
    cookies: bag,
    baseUsed: base
  };
}

/**
 * siweLogin(pk, opts)
 * opts: { proxyUrl, timeoutMs=20000, retries=2, allowNoProxyFallback=(env.ALLOW_NO_PROXY_ON_SIWE==='1'), altBases }
 */
export async function siweLogin(pk, opts={}){
  requireEnv(['PRIVY_BASE','NEURAVERSE_ORIGIN','DOMAIN','CHAIN_ID_NUM','PRIVY_APP_ID','PRIVY_CA_ID']);

  const {
    proxyUrl,
    timeoutMs = Number(process.env.SIWE_TIMEOUT_MS || 20000),
    retries = Number(process.env.SIWE_RETRIES || 2),
    allowNoProxyFallback = process.env.ALLOW_NO_PROXY_ON_SIWE === '1',
    altBases
  } = opts;

  const baseHeaders = {
    accept: 'application/json',
    'content-type': 'application/json',
    origin: process.env.NEURAVERSE_ORIGIN,
    referer: `${process.env.NEURAVERSE_ORIGIN}/`,
    'privy-app-id': process.env.PRIVY_APP_ID,
    'privy-ca-id':  process.env.PRIVY_CA_ID,
    'privy-client': 'react-auth:2.25.0',
    'user-agent': 'Mozilla/5.0 (CLI Privy Bot)',
  };

  const bases = (altBases && altBases.length)
    ? altBases
    : [ process.env.PRIVY_BASE, 'https://privy.neuraprotocol.io' ].filter(Boolean);

  let lastErr;
  for (const base of bases) {
    for (let i=0;i<=retries;i++){
      try {
        return await siweFlowOnce({ pk, base, proxyUrl, timeoutMs, baseHeaders });
      } catch (e) {
        lastErr = e;
        const transient = new Set(['ECONNABORTED','ETIMEDOUT','ECONNRESET','EAI_AGAIN','EPIPE']);
        const isTimeout = transient.has(e.code) || /timeout/i.test(e.message || '');
        if (isTimeout && allowNoProxyFallback && proxyUrl) {
          try {
            return await siweFlowOnce({ pk, base, proxyUrl: null, timeoutMs, baseHeaders });
          } catch(e2){ lastErr = e2; }
        }
        await sleep(300 + Math.random()*300);
      }
    }
  }
  throw lastErr || new Error('SIWE failed');
}

// ===== Public: forEachAccount =====
export async function forEachAccount({ keys, proxies=[], origin, cb }) {
  if (!Array.isArray(keys) || !keys.length) throw new Error('forEachAccount: keys required');
  const baseHeaders = {
    accept: 'application/json',
    'content-type': 'application/json',
    origin: origin || process.env.NEURAVERSE_ORIGIN,
    referer: `${origin || process.env.NEURAVERSE_ORIGIN}/`,
    'privy-app-id': process.env.PRIVY_APP_ID,
    'privy-ca-id':  process.env.PRIVY_CA_ID,
    'privy-client': 'react-auth:2.25.0',
    'user-agent': 'Mozilla/5.0 (CLI Privy Bot)'
  };

  const BETWEEN_MS = Number(process.env.BETWEEN_ACCOUNTS_MS || 1000);
  const PRIVY_BASE = process.env.PRIVY_BASE;

  for (let i=0;i<keys.length;i++){
    const pk = keys[i];
    const proxy = proxies.length ? proxies[i % proxies.length] : (process.env.PROXY || process.env.SOCKS_PROXY || process.env.HTTPS_PROXY || '');
    try {
      // login SIWE fresh untuk akun ini
      const login = await siweFlowOnce({ pk, base: PRIVY_BASE, proxyUrl: proxy, timeoutMs: Number(process.env.SIWE_TIMEOUT_MS || 20000), baseHeaders });
      const agents = makeAgents(proxy);
      const http = axios.create({
        ...agents,
        timeout: Number(process.env.HTTP_TIMEOUT || 45000),
        headers: { ...baseHeaders, authorization: `Bearer ${login.bearer}` },
        withCredentials: true,
        proxy: false,
        validateStatus: ()=>true
      });

      // cookies (opsional)
      const cookieBag = [];
      if (login.tokens.id_token)     cookieBag.push(`privy-id-token=${login.tokens.id_token}`);
      if (login.tokens.access_token) cookieBag.push(`privy-access-token=${login.tokens.access_token}`);
      if (login.tokens.privy_token)  cookieBag.push(`privy-token=${login.tokens.privy_token}`);
      if (cookieBag.length) http.defaults.headers.common['Cookie'] = cookieBag.join('; ');

      if (bool(process.env.DEBUG) || (process.env.log && process.env.log.level === 'debug')) {
        console.log('[dbg] session.set', { bearer: redact(login.bearer), cookies: cookieBag.length ? '(set)' : '(none)' });
      }

      await cb({ address: login.address, http, index: i+1, proxy, bearer: login.bearer });
    } catch (e) {
      console.log(`— forEachAccount error @idx=${i+1}:`, e.message || e);
    }
    if (i < keys.length-1 && BETWEEN_MS>0) await sleep(BETWEEN_MS);
  }
}

// ===== Public: getAuth (untuk modul yang hanya butuh bearer+address) =====
export async function getAuth(ctx){
  const { http, address } = ctx || {};
  const hasBearer = !!http?.defaults?.headers?.common?.authorization;
  if (!hasBearer) throw new Error('authorization header missing (bearer)');
  if (!address) throw new Error('address missing');
  return { http, address };
}

// default export (kompatibel dgn import core from …)
export default {
  getAuth,
  getPrivateKeys,
  getProxies,
  siweLogin,
  forEachAccount,
};
