#!/usr/bin/env node
import 'dotenv/config';
import axios from 'axios';
import { ethers } from 'ethers';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';

const sleep = (ms)=>new Promise(r=>setTimeout(r,ms));

function makeAgents(proxyUrl){
  if (!proxyUrl) return {};
  try {
    const p = String(proxyUrl).trim().toLowerCase();
    if (p.startsWith('socks')) { const a=new SocksProxyAgent(proxyUrl); return { httpAgent:a, httpsAgent:a }; }
    if (p.startsWith('http'))  { const a=new HttpsProxyAgent(proxyUrl); return { httpAgent:a, httpsAgent:a }; }
  } catch {}
  return {};
}

function redact(t,k=6){ return (!t||t.length<=k*2)?t:`${t.slice(0,k)}…${t.slice(-k)}`; }

function buildSiweMsg({ domain, uri, address, chainId, statement }){
  return `${domain} wants you to sign in with your Ethereum account:
${address}

${statement || 'By signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.'}

URI: ${uri}
Version: 1
Chain ID: ${chainId}
Nonce: $NONCE
Issued At: $ISSUED_AT
Resources:
- https://privy.io`;
}

async function siweFlowOnce({ pk, base, proxyUrl, timeoutMs }) {
  const wallet = new ethers.Wallet(pk);
  const address = wallet.address;

  const http = axios.create({
    baseURL: base,
    timeout: timeoutMs,
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      origin: process.env.NEURAVERSE_ORIGIN,
      referer: `${process.env.NEURAVERSE_ORIGIN}/`,
      'privy-app-id': process.env.PRIVY_APP_ID,
      'privy-ca-id':  process.env.PRIVY_CA_ID,
      'privy-client': 'react-auth:2.25.0',
      'user-agent': 'Mozilla/5.0 (CLI Privy Bot)'
    },
    withCredentials: true,
    proxy: false,
    ...makeAgents(proxyUrl),
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
  const message = msgTpl
    .replace('$NONCE', nonce)
    .replace('$ISSUED_AT', new Date().toISOString());
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
  // kalau 401/403, ulangi tanpa header auth/cookie (bersih)
  if (r2.status === 401 || r2.status === 403) {
    const { authorization, Cookie, ...rest } = http.defaults.headers.common || {};
    const clean = axios.create({
      baseURL: base, timeout: timeoutMs, headers: rest, withCredentials: true,
      proxy: false, ...makeAgents(proxyUrl), validateStatus: ()=>true
    });
    r2 = await clean.post('/api/v1/siwe/authenticate', payload);
  }
  if (r2.status >= 400) throw new Error(`siwe.authenticate ${r2.status}`);

  // AMBIL COOKIES + BEARER
  const setCookies = r2.headers?.['set-cookie'] || [];
  const bag = {};
  for (const sc of setCookies) {
    const m = String(sc).match(/^([^=]+)=([^;]+)/);
    if (m) bag[m[1]] = m[2];
  }
  const authData = r2.data || {};
  const bearer = authData.identity_token || authData.privy_access_token || authData.token || bag['privy-id-token'] || bag['privy-access-token'] || bag['privy-token'];

  if (!bearer) throw new Error('login ok tapi tidak ada bearer');

  return { address, bearer, cookies: bag, baseUsed: base };
}

/**
 * siweLogin — kuat terhadap timeout/jaringan
 * opsi:
 *   proxyUrl, timeoutMs (default 20000), retries (default 2), allowNoProxyFallback ('1' untuk aktif)
 *   altBases: array fallback bases (default: [process.env.PRIVY_BASE, 'https://privy.neuraprotocol.io'])
 */
export async function siweLogin(pk, opts={}){
  const {
    proxyUrl,
    timeoutMs = Number(process.env.SIWE_TIMEOUT_MS || 20000),
    retries = Number(process.env.SIWE_RETRIES || 2),
    allowNoProxyFallback = process.env.ALLOW_NO_PROXY_ON_SIWE === '1',
    altBases
  } = opts;

  const bases = (altBases && altBases.length)
    ? altBases
    : [ process.env.PRIVY_BASE, 'https://privy.neuraprotocol.io' ].filter(Boolean);

  let lastErr;
  // coba semua base, dengan retry per base
  for (const base of bases) {
    for (let i=0;i<=retries;i++){
      try {
        return await siweFlowOnce({ pk, base, proxyUrl, timeoutMs });
      } catch (e) {
        lastErr = e;
        // Kalau timeout & diizinkan fallback tanpa proxy → coba sekali tanpa proxy
        const isTimeout = (e.code==='ECONNABORTED') || /timeout/i.test(e.message || '');
        if (isTimeout && allowNoProxyFallback && proxyUrl) {
          try {
            return await siweFlowOnce({ pk, base, proxyUrl: null, timeoutMs });
          } catch(e2){ lastErr = e2; }
        }
        // delay kecil sebelum retry
        await sleep(300 + Math.random()*300);
      }
    }
  }
  throw lastErr || new Error('SIWE failed');
}
