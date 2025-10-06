#!/usr/bin/env node
/**
 * bridge.mjs — AUTO BRIDGE (login → whoami → bridge:visit → approve → deposit/transfer/custom)
 * Run: node bridge.mjs --fresh --debug
 */

import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import axios from 'axios';
import YAML from 'yaml';
import { ethers } from 'ethers';

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
} = process.env;

for (const k of ['PRIVATE_KEY','PRIVY_BASE','NEURAVERSE_ORIGIN','DOMAIN','CHAIN_ID_NUM']) {
  if (!process.env[k]) { console.error(`[ENV] ${k} is required`); process.exit(1); }
}
if (!SEPOLIA_RPC) { console.error('[ENV] SEPOLIA_RPC is required for bridge.mjs'); process.exit(1); }

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

const redact = (t, keep = 6) => (!t || typeof t !== 'string' || t.length <= keep*2) ? t : `${t.slice(0,keep)}…${t.slice(-keep)}`;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
let CFG = null;
const dbg = (...a) => { if ((CFG?.log?.level || 'info') === 'debug' || DEBUG) console.log('[dbg]', ...a); };

const isHtmlLike = s => !!s && typeof s === 'string' && (s.trimStart().startsWith('<!DOCTYPE') || s.includes('BAILOUT_TO_CLIENT_SIDE_RENDERING'));
function previewBody(data, headers) {
  const max = CFG?.log?.maxBodyChars ?? 180;
  const elideHtml = CFG?.log?.elideHtml !== false;
  const ctype = (headers?.['content-type'] || '').toLowerCase();
  if (elideHtml && (ctype.includes('text/html') || isHtmlLike(data))) return `[HTML omitted, ${typeof data==='string'?data.length:0} chars]`;
  if (data && typeof data === 'object') {
    const pick = {};
    if ('status' in data) pick.status = data.status;
    if ('message' in data) pick.message = data.message;
    try { const s = JSON.stringify(Object.keys(pick).length ? pick : data); return s.length>max ? s.slice(0,max)+'…' : s; } catch {}
  }
  if (typeof data === 'string') return data.length>max ? data.slice(0,max)+'…' : data;
  return String(data ?? '');
}
const compactLine = ({ method, url, status, ms, data, headers, tag='' }) =>
  `${tag?tag+' ':''}${(method||'REQ').toUpperCase()} ${url}${status?` ${status}`:''}${typeof ms==='number'?` (${ms}ms)`:''} → ${previewBody(data, headers)}`;

const DEFAULT_CFG = {
  flow: { whoami: true, visit: true },
  visitEvent: { type: 'bridge:visit', payload: {} },
  log: { level: 'info', maxBodyChars: 180, elideHtml: true, showHeaders: false },

  bridge: {
    mode: 'deposit',
    token: { symbol: 'ANKR', address: '0xB88Ca91Fef0874828e5ea830402e9089aaE0bB7F', decimals: 18 },
    spender: '0xC6255a594299f1776De376D0509AB5AB875A6E3E',
    amount: '1.0',
    recipient: '$OWNER',
    waitForReceipt: true,
    confirmations: 1,
    pollMs: 2500,
  },

  claim: { spam: 1, intervalMs: 2500, maxAttempts: 6, baseDelayMs: 1000, maxDelayMs: 8000 },
  events: { sendClaimEvent: true },
  balances: { networks: [] }
};
const DEFAULT_API = {
  endpoints: {
    appBase: 'https://neuraverse.neuraprotocol.io',
    infraBase: 'https://neuraverse-testnet.infra.neuraprotocol.io',
    claimPaths: ['/api/faucet','/api/faucet/claim','/api/faucet/claim-testnet','/api/claim'],
    eventsPath: '/api/events',
    accountPath: '/api/account'
  },
  claimBodies: [{ address: '$ADDRESS' }, { recipient: '$ADDRESS' }, { to: '$ADDRESS' }, {}]
};

function loadYaml(p, fallback) { try { const raw = fs.readFileSync(p,'utf8'); const cfg = YAML.parse(raw); dbg(`loaded ${path.basename(p)}`); return { ...fallback, ...cfg }; } catch { dbg(`using default (no ${path.basename(p)})`); return fallback; } }
function loadJson(p, fallback) { try { const raw = fs.readFileSync(p,'utf8'); const obj = JSON.parse(raw); dbg(`loaded ${path.basename(p)}`); return { ...fallback, ...obj }; } catch { dbg(`using default (no ${path.basename(p)})`); return fallback; } }
CFG = loadYaml(CONFIG_YAML, DEFAULT_CFG);
const API = loadJson(API_JSON, DEFAULT_API);

const { PRIVY_APP_ID, PRIVY_CA_ID } = process.env;
for (const k of ['PRIVY_APP_ID','PRIVY_CA_ID']) {
  if (!process.env[k]) { console.error(`[ENV] ${k} is required`); process.exit(1); }
}

function loadSession() { if (FRESH) return {}; try { return JSON.parse(fs.readFileSync(SESSION_FILE,'utf8')); } catch { return {}; } }
function saveSession(s) { fs.writeFileSync(SESSION_FILE, JSON.stringify(s,null,2)); setAuthHeadersFromSession(s); }

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
  if ((CFG.log?.level || 'info') === 'debug' || DEBUG) {
    const sh = CFG.log?.showHeaders;
    const headers = sh ? cfg.headers : {
      origin: cfg.headers?.origin,
      'privy-app-id': cfg.headers?.['privy-app-id'],
      authorization: cfg.headers?.authorization ? `Bearer ${redact(String(cfg.headers.authorization).slice(7))}` : undefined,
      Cookie: cfg.headers?.Cookie ? '(set)' : undefined,
    };
    console.log(compactLine({ method: cfg.method, url: cfg.url, data: cfg.data, headers, tag:'⇢' }));
  }
  return cfg;
});
http.interceptors.response.use(res => {
  const ms = Date.now() - (res.config.meta?.start || Date.now());
  const level = CFG.log?.level || 'info';
  if (level !== 'silent') console.log(compactLine({ method: res.config.method, url: res.config.url, status: res.status, ms, data: res.data, headers: res.headers, tag:'⇠' }));
  return res;
}, err => {
  const cfg = err.config || {};
  const ms = Date.now() - (cfg.meta?.start || Date.now());
  const status = err.response?.status, data = err.response?.data, headers = err.response?.headers;
  const level = CFG.log?.level || 'info';
  if (level !== 'silent') console.log(compactLine({ method: cfg.method, url: cfg.url, status, ms, data, headers, tag:'⇠' }));
  return Promise.reject(err);
});
function setAuthHeadersFromSession(sess) {
  const bearer = sess?.id_token || sess?.bearer || sess?.access_token;
  if (bearer) http.defaults.headers.common['authorization'] = `Bearer ${bearer}`; else delete http.defaults.headers.common['authorization'];
  const cookies = [];
  if (sess?.id_token)      cookies.push(`privy-id-token=${sess.id_token}`);
  if (sess?.access_token)  cookies.push(`privy-access-token=${sess.access_token}`);
  if (sess?.privy_token)   cookies.push(`privy-token=${sess.privy_token}`);
  if (sess?.refresh_token) cookies.push(`privy-refresh-token=${sess.refresh_token}`);
  if (sess?.session)       cookies.push(`privy-session=${sess.session}`);
  if (cookies.length) http.defaults.headers.common['Cookie'] = cookies.join('; '); else delete http.defaults.headers.common['Cookie'];
  if ((CFG.log?.level || 'info') === 'debug' || DEBUG) {
    console.log('[dbg] setAuthHeadersFromSession',
      SAFE_LOG_SECRETS==='1' ? '(redacted)' : {
        bearer: bearer ? redact(bearer) : '',
        id_token: sess?.id_token ? redact(sess.id_token) : null,
        access_token: sess?.access_token ? redact(sess.access_token) : null,
        privy_token: sess?.privy_token ? redact(sess.privy_token) : null,
        refresh_token: sess?.refresh_token ? redact(sess?.refresh_token) : null,
        session: sess?.session ? redact(sess?.session) : null,
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
async function siweInit(addr, { cleanHeaders=false } = {}) {
  if (cleanHeaders) {
    const { authorization, Cookie, ...rest } = http.defaults.headers.common;
    const tmp = axios.create({ ...http.defaults, headers: rest });
    return (await tmp.post(`${PRIVY_BASE}/api/v1/siwe/init`, { address: addr })).data;
  }
  return (await http.post(`${PRIVY_BASE}/api/v1/siwe/init`, { address: addr })).data;
}
async function siweAuthenticate({ message, signature }, { cleanHeaders=false } = {}) {
  const payload = { message, signature, chainId: CHAIN_NAMESPACE, walletClientType:'rabby_wallet', connectorType:'injected', mode:'login-or-sign-up' };
  const doPost = async (strip=false) => {
    if (strip) { const { authorization, Cookie, ...rest } = http.defaults.headers.common; const tmp = axios.create({ ...http.defaults, headers: rest }); return await tmp.post(`${PRIVY_BASE}/api/v1/siwe/authenticate`, payload); }
    return await http.post(`${PRIVY_BASE}/api/v1/siwe/authenticate`, payload);
  };
  let res;
  try { res = await doPost(false); } catch (e) {
    if (e.response?.status === 401 || e.response?.status === 403) { console.log('↻ authenticate retry without session headers…'); res = await doPost(true); }
    else throw e;
  }
  const data = res.data, setCookies = res.headers?.['set-cookie'] || [], cookieBag = {};
  for (const sc of setCookies) { const m = String(sc).match(/^([^=]+)=([^;]+)/); if (m) cookieBag[m[1]] = m[2]; }
  return { data, cookieBag };
}
async function ensureLogin() {
  const sess0 = loadSession();
  setAuthHeadersFromSession(sess0);
  try { await apiAccount(); console.log('✅ already logged in (session valid)'); return; }
  catch (e) { dbg('account check failed (will login):', e.response?.status, e.response?.data?.message || e.message); }
  console.log('🔐 login (SIWE)…');
  let init;
  try { init = await siweInit(address); }
  catch (e) {
    if (e.response?.status === 401 || e.response?.status === 403) { console.log('↻ init retry without session headers…'); init = await siweInit(address, { cleanHeaders:true }); }
    else throw e;
  }
  const nonce = init?.nonce || ethers.hexlify(ethers.randomBytes(16)).slice(2);
  const message = buildSiweMessage({ domain: DOMAIN, uri: NEURAVERSE_ORIGIN, address,
    statement:'By signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.',
    nonce, chainId: CHAIN_ID_NUM, issuedAt: new Date().toISOString() });
  const signature = await wallet.signMessage(message);
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
  if (!session.bearer) throw new Error('Login succeeded but no identity/access token found');
  saveSession(session);
  await apiAccount();
  console.log('✅ login ok');
}

function apiBases() { const { infraBase, eventsPath, accountPath } = API.endpoints; return { eventsURL: `${infraBase}${eventsPath}`, accountURL: `${infraBase}${accountPath}` }; }
async function apiAccount() { const { accountURL } = apiBases(); const { data } = await http.get(accountURL); return data; }
async function apiEventFlexible(desiredType, desiredPayload) {
  const { eventsURL } = apiBases();
  try { const { data } = await http.post(eventsURL, { type: desiredType, payload: desiredPayload }); return data; }
  catch (e) {
    const is422 = e.response?.status === 422;
    const text = typeof e.response?.data === 'string' ? e.response?.data : JSON.stringify(e.response?.data);
    const msg = (e.response?.data?.message || text || '').toLowerCase();
    if (is422 && msg.includes('expected object')) {
      const { data } = await http.post(eventsURL, { type: desiredType, payload: {} });
      return data;
    }
    throw e;
  }
}

function tryChecksum(addr) {
  try { return ethers.getAddress(addr); }
  catch {
    if (typeof addr === 'string') {
      const low = addr.toLowerCase();
      if (/^0x[0-9a-f]{40}$/.test(low)) return ethers.getAddress(low);
    }
    throw new Error('bad address checksum');
  }
}
function safeChecksum(label, addr, { allowEmpty=false } = {}) {
  if (!addr) {
    if (allowEmpty) return null;
    throw new Error(`Missing ${label} in config.yaml (got: ${addr}). Please set "${label}" to a valid 0x-address.`);
  }
  try {
    const checksummed = tryChecksum(addr);
    if ((CFG.log?.level || 'info') !== 'silent') console.log(`ℹ️ ${label} → ${checksummed}`);
    return checksummed;
  } catch {
    throw new Error(`Invalid ${label} address: ${addr}`);
  }
}
const resolveRecipient = v => (!v || v === '$OWNER') ? address : v;
function materializeArgs(args, vars) {
  if (!Array.isArray(args)) return [];
  return args.map(a => (typeof a !== 'string') ? a : (
    a === '$TOKEN' ? vars.TOKEN :
    a === '$AMOUNT' ? vars.AMOUNT :
    a === '$OWNER' ? vars.OWNER :
    a === '$RECIPIENT' ? vars.RECIPIENT : a
  ));
}

const ERC20_ABI = [
  'function balanceOf(address) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
  'function allowance(address owner, address spender) view returns (uint256)',
  'function approve(address spender, uint256 value) returns (bool)',
  'function transfer(address to, uint256 value) returns (bool)',
];

async function ensureAllowance(provider, tokenAddr, owner, spender, wantAmount, decimals) {
  const signer = new ethers.Wallet(PRIVATE_KEY, provider);
  const erc20  = new ethers.Contract(tokenAddr, ERC20_ABI, signer);
  const [current, symbol] = await Promise.all([ erc20.allowance(owner, spender), erc20.symbol().catch(()=>'TOKEN') ]);
  const fmt = (v) => ethers.formatUnits(v, decimals);
  console.log('🔗 Bridge approve on Sepolia');
  console.log(`  Token     : ${symbol} @ ${tokenAddr}`);
  console.log(`  Spender   : ${spender}`);
  console.log(`  Owner     : ${owner}`);
  console.log(`  Amount    : ${ethers.formatUnits(wantAmount, decimals)} (${wantAmount.toString()})`);
  console.log(`  Allowance : ${fmt(current)} ${symbol}`);
  if (current >= wantAmount) { console.log('✅ enough allowance; skipping approve'); return; }
  const tx = await erc20.approve(spender, wantAmount);
  console.log(`📝 approve tx sent: ${tx.hash}`);
  if (CFG.bridge.waitForReceipt) {
    const r = await tx.wait(Math.max(0, Number(CFG.bridge.confirmations ?? 1)));
    if (r?.status === 1) console.log(`🎉 approve confirmed in block ${r.blockNumber} (status=1)`);
    else                 console.log(`⚠️ approve mined but status != 1 (block ${r?.blockNumber ?? '?'})`);
  }
}

async function performDeposit(provider, tokenAddr, amount, decimals) {
  const BR = CFG.bridge;

  if (BR?.tx && BR.tx.to && BR.tx.abi && BR.tx.method) {
    const to = safeChecksum('bridge.tx.to', BR.tx.to);
    const iface = new ethers.Interface(BR.tx.abi);
    const recipient = resolveRecipient(BR.recipient) || address;
    const callArgs = materializeArgs(BR.tx.args, { TOKEN: tokenAddr, AMOUNT: amount, OWNER: address, RECIPIENT: recipient });
    const data = iface.encodeFunctionData(BR.tx.method, callArgs);
    const value = BR.tx.value ? ethers.parseEther(String(BR.tx.value)) : 0n;
    const signer = new ethers.Wallet(PRIVATE_KEY, provider);
    const tx = await signer.sendTransaction({ to, data, value });
    console.log(`📝 deposit tx sent: ${tx.hash}`);
    const confs = Math.max(0, Number(BR.confirmations ?? 1));
    if (BR.waitForReceipt) {
      const r = await tx.wait(confs);
      if (r?.status === 1) console.log(`🎉 deposit confirmed in block ${r.blockNumber} (status=1)`);
      else                 console.log(`⚠️ deposit mined but status != 1 (block ${r?.blockNumber ?? '?'})`);
    }
    return;
  }

  if (BR.useTransfer) {
    const signer = new ethers.Wallet(PRIVATE_KEY, provider);
    const token  = new ethers.Contract(tokenAddr, ERC20_ABI, signer);
    const spender = safeChecksum('spender', BR.spender);
    console.log(`🚚 transfer fallback → ${spender}, amount ${ethers.formatUnits(amount, decimals)}`);
    const tx = await token.transfer(spender, amount);
    console.log(`📝 transfer tx sent: ${tx.hash}`);
    const confs = Math.max(0, Number(BR.confirmations ?? 1));
    if (BR.waitForReceipt) {
      const r = await tx.wait(confs);
      if (r?.status === 1) console.log(`🎉 transfer confirmed in block ${r.blockNumber} (status=1)`);
      else                 console.log(`⚠️ transfer mined but status != 1 (block ${r?.blockNumber ?? '?'})`);
    }
    return;
  }

  const bridgeTo = safeChecksum('spender/bridge', BR.spender);
  if (BR.spender !== bridgeTo) console.log(`ℹ️ fixed spender checksum → ${bridgeTo}`);
  const iface = new ethers.Interface(['function deposit(uint256 _amount, address _recipient)']);
  const recipient = resolveRecipient(BR.recipient) || address;
  const data = iface.encodeFunctionData('deposit', [amount, recipient]);
  const signer = new ethers.Wallet(PRIVATE_KEY, provider);
  const tx = await signer.sendTransaction({ to: bridgeTo, data, value: 0n });
  console.log(`📝 deposit tx sent: ${tx.hash}`);
  const confs = Math.max(0, Number(BR.confirmations ?? 1));
  if (CFG.bridge.waitForReceipt) {
    const r = await tx.wait(confs);
    if (r?.status === 1) console.log(`🎉 deposit confirmed in block ${r.blockNumber} (status=1)`);
    else                 console.log(`⚠️ deposit mined but status != 1 (block ${r?.blockNumber ?? '?'})`);
  }
}

(async () => {
  try {
    console.log('Address :', address);
    console.log('Domain  :', DOMAIN);
    console.log('ChainID :', CHAIN_ID_NUM);
    if (SEPOLIA_RPC) console.log('ChainID : sepolia = yes (for bridge source)');

    await ensureLogin();

    if (CFG.flow?.whoami) {
      try {
        const acct = await apiAccount();
        console.log('👤 /api/account →');
        console.log(`  address       : ${acct?.address || '-'}`);
        const np = Number(acct?.neuraPoints ?? 0);
        console.log(`  neuraPoints   : ${isNaN(np) ? '-' : np}`);
        const tvm = Number(acct?.tradingVolume?.month ?? 0);
        const tva = Number(acct?.tradingVolume?.allTime ?? 0);
        console.log(`  tradingVolume : month=${isNaN(tvm) ? '-' : tvm} | allTime=${isNaN(tva) ? '-' : tva}`);
      } catch (e) {
        console.log('⚠️ /api/account failed:', e.response?.status || '', e.response?.data?.message || e.message);
      }
    }

    if (CFG.flow?.visit) {
      const BRV = CFG.bridge?.visitEvent;
      const GV  = CFG.visitEvent;
      const evType = (BRV?.type || GV?.type || 'bridge:visit');
      const evPayload = (BRV?.payload ?? GV?.payload ?? {});
      try { await apiEventFlexible(evType, evPayload); console.log('🧭 Logged bridge visit event.'); }
      catch (e) { console.log('⚠️ visit event failed:', e.response?.status || '', e.response?.data?.message || e.message); }
    }

    const BR = CFG.bridge || {};
    const tokenAddr = safeChecksum('token.address', BR.token?.address);
    const decimals  = Number(BR.token?.decimals ?? 18);
    const humanAmt  = String(BR.amount ?? '0');
    const want      = ethers.parseUnits(humanAmt, decimals);

    if (!BR.tx || !BR.tx.to) {
      try { safeChecksum('spender', BR.spender); }
      catch (e) {
        console.error(`❌ spender is invalid or missing.\n   Read from config: ${BR.spender ?? '(undefined)'}\n   Fix "bridge.spender" in config.yaml to a valid 0x-address (checksummed or lowercase).`);
        throw e;
      }
    }

    const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC);

    if (!BR.useTransfer) {
      const spender = safeChecksum('spender', BR.spender);
      await ensureAllowance(provider, tokenAddr, address, spender, want, decimals);
    }

    await performDeposit(provider, tokenAddr, want, decimals);

  } catch (e) {
    if (e?.code === 'BAD_DATA' && /decode/i.test(e.message || '')) {
      console.error('❌ decode error — likely wrong ABI or endpoint. Details:', e.message);
    } else if (String(e.message || '').toLowerCase().includes('invalid') && String(e.message || '').toLowerCase().includes('address')) {
      console.error('❌ address error — check `spender` and `token.address` in config.yaml');
    } else if (String(e.message || '').toLowerCase().includes('checksum')) {
      console.error('❌ address checksum error — verify hex of `spender` / `token.address`');
    } else {
      console.error('[fatal]', e.response?.status || '', e.response?.data ?? e.stack ?? e.message);
    }
    process.exit(1);
  }
})();
