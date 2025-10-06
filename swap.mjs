#!/usr/bin/env node
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
} = process.env;

for (const k of ['PRIVATE_KEY','NEURA_RPC','PRIVY_BASE','NEURAVERSE_ORIGIN','DOMAIN','CHAIN_ID_NUM']) {
  if (!process.env[k]) { console.error(`[ENV] ${k} is required`); process.exit(1); }
}

const argv = new Map(process.argv.slice(2).map(s => {
  const m = s.match(/^--([^=]+)(=(.*))?$/); return m ? [m[1], m[3] ?? '1'] : [s, '1'];
}));
const DEBUG = ENV_DEBUG === '1' || argv.has('debug');
const FRESH = argv.has('fresh');
const AMOUNT_OVERRIDE = argv.get('amount');              
const ROUTE_FILTER = argv.has('route') ? Number(argv.get('route')) : null;

const wallet = new ethers.Wallet(PRIVATE_KEY);
const address = wallet.address;
const CHAIN_NAMESPACE = `eip155:${CHAIN_ID_NUM}`;

const ROOT = process.cwd();
const SESSION_FILE = path.resolve(ROOT, 'privy-session.json');
const CONFIG_YAML = path.resolve(ROOT, 'config.yaml');
const API_JSON    = path.resolve(ROOT, 'api.json');

const redact = (t, keep = 6) => (!t || typeof t !== 'string' || t.length <= keep*2) ? t : `${t.slice(0,keep)}…${t.slice(-keep)}`;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const loadYaml = (p) => YAML.parse(fs.readFileSync(p, 'utf8'));
const loadJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));

let CFG, API;
try { CFG = loadYaml(CONFIG_YAML); } catch { console.error('config.yaml not found / invalid YAML'); process.exit(1); }
try { API = loadJson(API_JSON); } catch { console.error('api.json not found / invalid JSON'); process.exit(1); }

const isDebug = () => (CFG?.log?.level || 'info') === 'debug' || DEBUG;
const dbg = (...a) => { if (isDebug()) console.log('[dbg]', ...a); };

const isHtmlLike = s => !!s && typeof s === 'string' && (s.trimStart().startsWith('<!DOCTYPE') || s.includes('BAILOUT_TO_CLIENT_SIDE_RENDERING'));
function previewBody(data, headers, max = CFG?.log?.maxBodyChars ?? 180, elideHtml = CFG?.log?.elideHtml !== false) {
  const ctype = (headers?.['content-type'] || '').toLowerCase();
  if (elideHtml && (ctype.includes('text/html') || isHtmlLike(data))) return `[HTML omitted]`;
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
  if (isDebug()) console.log(compactLine({ method: res.config.method, url: res.config.url, status: res.status, ms, data: res.data, headers: res.headers, tag:'⇠' }));
  return res;
}, err => {
  const cfg = err.config || {};
  const ms = Date.now() - (cfg.meta?.start || Date.now());
  if (isDebug()) console.log(compactLine({ method: cfg.method, url: cfg.url, status: err.response?.status, ms, data: err.response?.data, headers: err.response?.headers, tag:'⇠' }));
  return Promise.reject(err);
});

function loadSession() { if (FRESH) return {}; try { return JSON.parse(fs.readFileSync(SESSION_FILE,'utf8')); } catch { return {}; } }
function saveSession(s) { fs.writeFileSync(SESSION_FILE, JSON.stringify(s,null,2)); setAuthHeadersFromSession(s); }
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
  if (isDebug()) console.log('[dbg] setAuthHeadersFromSession', SAFE_LOG_SECRETS==='1' ? '(redacted)' : { bearer: bearer?redact(bearer):'' });
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
async function siweInit(addr) { return (await http.post(`${PRIVY_BASE}/api/v1/siwe/init`, { address: addr })).data; }
async function siweAuthenticate({ message, signature }) {
  const payload = { message, signature, chainId: CHAIN_NAMESPACE, walletClientType:'rabby_wallet', connectorType:'injected', mode:'login-or-sign-up' };
  const res = await http.post(`${PRIVY_BASE}/api/v1/siwe/authenticate`, payload);
  const data = res.data, setCookies = res.headers?.['set-cookie'] || [], bag = {};
  for (const sc of setCookies) { const m = String(sc).match(/^([^=]+)=([^;]+)/); if (m) bag[m[1]] = m[2]; }
  return { data, cookieBag: bag };
}
async function ensureLogin() {
  try { await apiAccount(); console.log('✅ already logged in (session valid)'); return; }
  catch {}
  const init = await siweInit(address);
  const nonce = init?.nonce || ethers.hexlify(ethers.randomBytes(16)).slice(2);
  const message = buildSiweMessage({ domain: DOMAIN, uri: NEURAVERSE_ORIGIN, address,
    statement:'By signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.',
    nonce, chainId: CHAIN_ID_NUM, issuedAt: new Date().toISOString() });
  const signature = await wallet.signMessage(message);
  const { data: authData, cookieBag } = await siweAuthenticate({ message, signature });
  const session = loadSession();
  if (authData?.identity_token) session.id_token = authData.identity_token;
  if (authData?.privy_access_token) session.access_token = authData.privy_access_token;
  if (authData?.token) session.privy_token = authData.token;
  if (cookieBag['privy-id-token'])      session.id_token = cookieBag['privy-id-token'];
  if (cookieBag['privy-access-token'])  session.access_token = cookieBag['privy-access-token'];
  if (cookieBag['privy-token'])         session.privy_token = cookieBag['privy-token'];
  if (cookieBag['privy-session'])       session.session = cookieBag['privy-session'];
  session.bearer = session.id_token || session.access_token || session.privy_token;
  if (!session.bearer) throw new Error('Login succeeded but no identity/access token found');
  saveSession(session);
  await apiAccount();
  console.log('✅ login ok');
}

function apiBases() {
  const ep = API.endpoints || {};
  return {
    eventsURL: `${ep.infraBase}${ep.eventsPath}`,
    accountURL: `${ep.infraBase}${ep.accountPath}`,
    subgraphUrl: ep.subgraphUrl
  };
}
async function apiAccount() {
  const { accountURL } = apiBases();
  const { data } = await http.get(accountURL);
  return data;
}
async function postVisitQuiet(type = 'swap:visit', payload = {}) {
  const { eventsURL } = apiBases();
  try { await http.post(eventsURL, { type, payload }); } catch {}
}
async function fetchPools(poolIds) {
  const { subgraphUrl } = apiBases();
  if (!subgraphUrl) throw new Error('Missing endpoints.subgraphUrl in api.json');
  const query = `
    query MultiplePools($poolIds: [ID!]) {
      pools(where: {id_in: $poolIds}) {
        id fee
        token0 { id symbol name decimals derivedMatic }
        token1 { id symbol name decimals derivedMatic }
        sqrtPrice liquidity tick tickSpacing
        totalValueLockedUSD volumeUSD feesUSD untrackedFeesUSD
        token0Price token1Price
      }
    }`;
  const { data } = await axios.post(subgraphUrl, {
    operationName: 'MultiplePools',
    variables: { poolIds },
    query
  }, { headers: { 'content-type': 'application/json', accept: '*/*', origin: NEURAVERSE_ORIGIN, referer: `${NEURAVERSE_ORIGIN}/` } });
  return data?.data?.pools || [];
}

const POW10 = (n) => 10n ** BigInt(n);
function toScaled18(s) {
  const t = String(s).trim();
  if (!t.includes('.')) return BigInt(t) * POW10(18);
  const [i, fRaw] = t.split('.');
  const f = fRaw.slice(0,18);
  const pad = 18 - f.length;
  const intScaled = BigInt(i || '0') * POW10(18);
  const fracScaled = BigInt(f || '0') * POW10(pad);
  return t.startsWith('-') ? -(intScaled + fracScaled) : (intScaled + fracScaled);
}
function estimateOut(amountInWei, tokenIn, tokenOut, pool) {
  const t0 = ethers.getAddress(pool.token0.id), t1 = ethers.getAddress(pool.token1.id);
  const a  = ethers.getAddress(tokenIn.address), b  = ethers.getAddress(tokenOut.address);
  const decIn = BigInt(tokenIn.decimals), decOut = BigInt(tokenOut.decimals);
  const scale = POW10(18);
  let pScaled;
  if (a === t0 && b === t1)      pScaled = toScaled18(pool.token0Price);
  else if (a === t1 && b === t0) pScaled = toScaled18(pool.token1Price);
  else return 0n;
  const diff = decOut - decIn;
  if (diff >= 0n) return (amountInWei * pScaled * POW10(Number(diff))) / scale;
  return (amountInWei * pScaled) / (scale * POW10(Number(-diff)));
}
const applySlippage = (out, bps) => out - (out * BigInt(bps) / 10000n);
const fmt = (n, d) => ethers.formatUnits(n, d);
const toBig = (n, d) => ethers.parseUnits(String(n), d);

const ERC20_ABI = [
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
  'function balanceOf(address) view returns (uint256)',
  'function allowance(address owner, address spender) view returns (uint256)',
  'function approve(address spender, uint256 value) returns (bool)',
];
async function getErc20Balance(provider, token, owner) {
  const c = new ethers.Contract(token.address, ERC20_ABI, provider);
  return await c.balanceOf(owner);
}
async function ensureAllowance(provider, tokenAddr, owner, spender, wantAmount, decimals) {
  const signer = new ethers.Wallet(PRIVATE_KEY, provider);
  const erc20  = new ethers.Contract(tokenAddr, ERC20_ABI, signer);
  const [allow, sym] = await Promise.all([ erc20.allowance(owner, spender), erc20.symbol().catch(()=> 'TOKEN') ]);
  console.log('🔗 Approve (if needed)');
  console.log(`  Token     : ${sym} @ ${tokenAddr}`);
  console.log(`  Spender   : ${spender}`);
  console.log(`  Owner     : ${owner}`);
  console.log(`  AmountIn  : ${fmt(wantAmount, decimals)} (${wantAmount.toString()})`);
  console.log(`  Allowance : ${fmt(allow, decimals)} ${sym}`);
  if (allow >= wantAmount) { console.log('✅ enough allowance; skip approve'); return; }
  const tx = await erc20.approve(spender, wantAmount);
  console.log(`📝 approve tx: ${tx.hash}`);
  const confs = Math.max(0, Number(CFG.swap?.confirmations ?? 1));
  if (CFG.swap?.waitForReceipt ?? true) {
    const r = await tx.wait(confs);
    console.log(r?.status === 1 ? `🎉 approve confirmed (block ${r.blockNumber})` : `⚠️ approve mined with status ${r?.status}`);
  }
}

function tryChecksum(addr) {
  try { return ethers.getAddress(addr); }
  catch { const low = String(addr||'').toLowerCase(); if (/^0x[0-9a-f]{40}$/.test(low)) return ethers.getAddress(low); throw new Error('bad address checksum'); }
}
function materializeArgs(args, vars) {
  if (!Array.isArray(args)) return args;
  return args.map(v => {
    if (typeof v !== 'string') return v;
    return ({
      '$TOKEN_IN': vars.TOKEN_IN, '$TOKEN_OUT': vars.TOKEN_OUT,
      '$AMOUNT_IN': vars.AMOUNT_IN, '$MIN_OUT': vars.MIN_OUT,
      '$RECIPIENT': vars.RECIPIENT, '$POOL_FEE': vars.POOL_FEE,
      '$DEADLINE': vars.DEADLINE
    }[v]) ?? v;
  });
}
async function doRouterSwap(provider, route, quote) {
  const txCfg = route?.tx || CFG.swap?.tx;
  if (!txCfg?.to || !txCfg?.abi || !txCfg?.method) {
    console.log('ℹ️ No router configured (swap.tx missing). Dry-run only (no onchain swap).');
    return;
  }
  const to = tryChecksum(txCfg.to);
  const iface = new ethers.Interface(txCfg.abi);
  const recipient = (route?.recipient || CFG.swap?.recipient || '$OWNER') === '$OWNER' ? address : (route?.recipient || CFG.swap?.recipient);
  const deadline = Math.floor(Date.now()/1000) + 60 * 10;

  const vars = {
    TOKEN_IN:  tryChecksum(route.tokenIn.address),
    TOKEN_OUT: tryChecksum(route.tokenOut.address),
    AMOUNT_IN: quote.amountIn,
    MIN_OUT:   quote.minOut,
    RECIPIENT: recipient,
    POOL_FEE:  Number(route.poolFee ?? CFG.swap?.poolFee ?? 500),
    DEADLINE:  BigInt(deadline),
  };
  const args = materializeArgs(txCfg.args, vars);
  const data = iface.encodeFunctionData(txCfg.method, args);
  const value = txCfg.value ? ethers.parseEther(String(txCfg.value)) : 0n;

  await ensureAllowance(provider, vars.TOKEN_IN, address, to, quote.amountIn, route.tokenIn.decimals);

  const signer = new ethers.Wallet(PRIVATE_KEY, provider);
  const tx = await signer.sendTransaction({ to, data, value });
  console.log(`📝 swap tx: ${tx.hash}`);
  const confs = Math.max(0, Number(route.confirmations ?? CFG.swap?.confirmations ?? 1));
  if ((route.waitForReceipt ?? CFG.swap?.waitForReceipt) ?? true) {
    const r = await tx.wait(confs);
    console.log(r?.status === 1 ? `🎉 swap confirmed (block ${r.blockNumber})` : `⚠️ swap mined with status ${r?.status}`);
  }
}

(async () => {
  try {
    console.log('Address :', address);

    await ensureLogin();

    if (CFG.flow?.whoami) {
      try {
        const acct = await apiAccount();
        console.log('👤 /api/account →');
        console.log(`  address       : ${acct?.address || '-'}`);
        console.log(`  neuraPoints   : ${Number(acct?.neuraPoints ?? 0)}`);
        console.log(`  tradingVolume : month=${Number(acct?.tradingVolume?.month ?? 0)} | allTime=${Number(acct?.tradingVolume?.allTime ?? 0)}`);
      } catch (e) {
        console.log('⚠️ /api/account failed:', e.response?.status || '', e.response?.data?.message || e.message);
      }
    }

    if (CFG.flow?.visit) {
      const ev = CFG.visitEvent || { type: 'swap:visit', payload: {} };
      await postVisitQuiet(ev.type || 'swap:visit', ev.payload ?? {});
    }

    const SW = CFG.swap || {};
    let routes = Array.isArray(SW.routes) && SW.routes.length ? SW.routes : [{
      pools: SW.pools || [],
      tokenIn: SW.tokenIn, tokenOut: SW.tokenOut,
      amountIn: SW.amountIn, slippageBps: SW.slippageBps,
      waitForReceipt: SW.waitForReceipt, confirmations: SW.confirmations,
      enforceBalance: SW.enforceBalance, poolFee: SW.poolFee, tx: SW.tx, recipient: SW.recipient,
    }];

    if (ROUTE_FILTER !== null) {
      if (ROUTE_FILTER < 0 || ROUTE_FILTER >= routes.length) { console.error(`Invalid --route index ${ROUTE_FILTER}`); process.exit(1); }
      routes = [routes[ROUTE_FILTER]];
    }

    const provider = new ethers.JsonRpcProvider(NEURA_RPC);
    const delayMs = Math.max(0, Number(SW.delayMs ?? 3000));

    for (let i = 0; i < routes.length; i++) {
      const r = routes[i];

      const amountHuman = AMOUNT_OVERRIDE ?? r.amountIn ?? SW.amountIn ?? '0';
      const amountIn = ethers.parseUnits(String(amountHuman), r.tokenIn.decimals);

      const poolIds = Array.isArray(r.pools) && r.pools.length ? r.pools : (Array.isArray(SW.pools) ? SW.pools : []);
      const pools = poolIds.length ? await fetchPools(poolIds) : [];
      if (!pools.length) {
        console.log(`⚠️ [route ${i}] No pools returned by subgraph.`);
      } else {
        console.log(`📊 [route ${i}] Pools: ${pools.length}`);
        for (const p of pools) {
          console.log(`  - ${p.id}`);
          console.log(`    pair: ${p.token0.symbol}/${p.token1.symbol} fee=${p.fee}`);
          console.log(`    t0Price=${p.token0Price} t1Price=${p.token1Price} TVL=$${p.totalValueLockedUSD}`);
        }
      }

      let usedPool = null;
      for (const p of pools) {
        const t0 = ethers.getAddress(p.token0.id);
        const t1 = ethers.getAddress(p.token1.id);
        const a0 = ethers.getAddress(r.tokenIn.address);
        const b0 = ethers.getAddress(r.tokenOut.address);
        if ((a0 === t0 && b0 === t1) || (a0 === t1 && b0 === t0)) { usedPool = p; break; }
      }

      const estOut = usedPool ? estimateOut(amountIn, r.tokenIn, r.tokenOut, usedPool) : 0n;
      const minOut = applySlippage(estOut, BigInt(r.slippageBps ?? SW.slippageBps ?? 100));

      const balIn = await getErc20Balance(provider, r.tokenIn, address);
      console.log(`💼 [route ${i}] Balance ${r.tokenIn.symbol}: ${fmt(balIn, r.tokenIn.decimals)}`);
      if (balIn < amountIn) {
        const msg = `❌ [route ${i}] insufficient ${r.tokenIn.symbol}: need ${fmt(amountIn,r.tokenIn.decimals)}, have ${fmt(balIn,r.tokenIn.decimals)}`;
        if ((r.enforceBalance ?? SW.enforceBalance) !== false) { console.log(msg + ' — skip route'); }
        else { console.log(msg + ' — continue (enforceBalance=false)'); }
        if (i < routes.length - 1 && delayMs) await sleep(delayMs);
        continue;
      }

      console.log(`💱 [route ${i}] Plan`);
      console.log(`  tokenIn   : ${r.tokenIn.symbol} @ ${ethers.getAddress(r.tokenIn.address)}`);
      console.log(`  tokenOut  : ${r.tokenOut.symbol} @ ${ethers.getAddress(r.tokenOut.address)}`);
      console.log(`  amountIn  : ${fmt(amountIn, r.tokenIn.decimals)} ${r.tokenIn.symbol}`);
      console.log(`  estOut    : ${usedPool ? fmt(estOut, r.tokenOut.decimals) : '-'} ${r.tokenOut.symbol}`);
      console.log(`  minOut    : ${usedPool ? fmt(minOut, r.tokenOut.decimals) : '-'} ${r.tokenOut.symbol} (slippage ${r.slippageBps ?? SW.slippageBps ?? 100} bps)`);
      if (usedPool) console.log(`  poolUsed  : ${usedPool.id} (${usedPool.token0.symbol}/${usedPool.token1.symbol}, fee=${usedPool.fee})`);

      await doRouterSwap(provider, r, { amountIn, minOut });

      if (i < routes.length - 1 && delayMs) {
        if (isDebug()) console.log(`[dbg] delay ${delayMs}ms before next route`);
        await sleep(delayMs);
      }
    }

  } catch (e) {
    if (e?.code === 'BAD_DATA' && /decode/i.test(e.message || '')) {
      console.error('❌ decode error — wrong ABI or endpoint.');
    } else if (String(e.message || '').toLowerCase().includes('address')) {
      console.error('❌ address error — verify token/router addresses in config.yaml');
    } else if (String(e.message || '').toLowerCase().includes('checksum')) {
      console.error('❌ checksum error — use checksummed/lowercase 0x addresses');
    } else {
      console.error('[fatal]', e.response?.status || '', e.response?.data ?? e.stack ?? e.message);
    }
    process.exit(1);
  }
})();
