#!/usr/bin/env node
import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import axios from 'axios';
import YAML from 'yaml';
import { ethers } from 'ethers';

const {
  PRIVATE_KEY, PRIVY_BASE, NEURAVERSE_ORIGIN, DOMAIN, CHAIN_ID_NUM,
  DEBUG: ENV_DEBUG, SAFE_LOG_SECRETS = '1',
} = process.env;

for (const k of ['PRIVATE_KEY','PRIVY_BASE','NEURAVERSE_ORIGIN','DOMAIN','CHAIN_ID_NUM']) {
  if (!process.env[k]) { console.error(`[ENV] ${k} is required`); process.exit(1); }
}

const argv = new Map(process.argv.slice(2).map(s => {
  const m = s.match(/^--([^=]+)(=(.*))?$/); return m ? [m[1], m[3] ?? '1'] : [s,'1'];
}));
const DEBUG    = ENV_DEBUG === '1' || argv.has('debug');
const FRESH    = argv.has('fresh');
const NO_LB    = argv.has('no-lb');
const NO_LIST  = argv.has('no-list');
const NO_CLAIM = argv.has('no-claim');

const wallet = new ethers.Wallet(PRIVATE_KEY);
const address = wallet.address;
const CHAIN_NAMESPACE = `eip155:${CHAIN_ID_NUM}`;

const ROOT = process.cwd();
const SESSION_FILE = path.resolve(ROOT, 'privy-session.json');
const CONFIG_YAML = path.resolve(ROOT, 'config.yaml');
const API_JSON    = path.resolve(ROOT, 'api.json');

const redact = (t, keep=6) => (!t || typeof t!=='string' || t.length<=keep*2) ? t : `${t.slice(0,keep)}…${t.slice(-keep)}`;
const loadYaml = p => { try { return YAML.parse(fs.readFileSync(p,'utf8')); } catch { return {}; } };
const loadJson = p => { try { return JSON.parse(fs.readFileSync(p,'utf8')); } catch { return {}; } };
const CFG = loadYaml(CONFIG_YAML);
const API = loadJson(API_JSON);
const isDebug = () => (CFG?.log?.level || 'info') === 'debug' || DEBUG;

const http = axios.create({
  timeout: 25000,
  headers: {
    accept: 'application/json',
    'content-type': 'application/json',
    origin: NEURAVERSE_ORIGIN,
    referer: `${NEURAVERSE_ORIGIN}/`,
    'privy-app-id': PRIVY_APP_ID,  
    'privy-ca-id':  PRIVY_CA_ID,    
    'privy-client': 'react-auth:2.25.0',
    'user-agent': 'Mozilla/5.0 (CLI Privy Bot)',
  },
  withCredentials: true,
});
http.interceptors.request.use(cfg=>{
  cfg.meta = { start: Date.now() };
  if (isDebug()) {
    const headers = {
      origin: cfg.headers?.origin,
      'privy-app-id': cfg.headers?.['privy-app-id'],
      authorization: cfg.headers?.authorization ? `Bearer ${redact(String(cfg.headers.authorization).slice(7))}` : undefined,
      Cookie: cfg.headers?.Cookie ? '(set)' : undefined,
    };
    console.log('⇢', (cfg.method||'').toUpperCase(), cfg.url, JSON.stringify(cfg.data ?? ''), headers);
  }
  return cfg;
});
http.interceptors.response.use(res=>{
  const ms = Date.now() - (res.config.meta?.start || Date.now());
  if (isDebug()) console.log('⇠', res.status, res.config.url, `(${ms}ms)`,
    typeof res.data==='object' ? JSON.stringify(res.data).slice(0,200)+'…' : String(res.data).slice(0,200)+'…');
  return res;
}, err=>{
  const cfg = err.config || {};
  const ms = Date.now() - (cfg.meta?.start || Date.now());
  if (isDebug()) console.log('⇠', err.response?.status || 'ERR', cfg.url, `(${ms}ms)`, err.response?.data || err.message);
  return Promise.reject(err);
});

function loadSession(){ if (FRESH) return {}; try { return JSON.parse(fs.readFileSync(SESSION_FILE,'utf8')); } catch { return {}; } }
function saveSession(s){ fs.writeFileSync(SESSION_FILE, JSON.stringify(s,null,2)); setAuthHeadersFromSession(s); }
function setAuthHeadersFromSession(sess){
  const bearer = sess?.id_token || sess?.bearer || sess?.access_token;
  if (bearer) http.defaults.headers.common['authorization'] = `Bearer ${bearer}`; else delete http.defaults.headers.common['authorization'];
  const cookies = [];
  if (sess?.id_token) cookies.push(`privy-id-token=${sess.id_token}`);
  if (sess?.access_token) cookies.push(`privy-access-token=${sess.access_token}`);
  if (sess?.privy_token) cookies.push(`privy-token=${sess.privy_token}`);
  if (sess?.refresh_token) cookies.push(`privy-refresh-token=${sess.refresh_token}`);
  if (sess?.session) cookies.push(`privy-session=${sess.session}`);
  if (cookies.length) http.defaults.headers.common['Cookie'] = cookies.join('; '); else delete http.defaults.headers.common['Cookie'];
  if (isDebug()) console.log('[dbg] session set', SAFE_LOG_SECRETS==='1' ? '(redacted)' : { bearer: bearer?redact(bearer):'' });
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
async function siweInit(addr){ return (await http.post(`${PRIVY_BASE}/api/v1/siwe/init`, { address: addr })).data; }
async function siweAuthenticate({ message, signature }){
  const payload = { message, signature, chainId: CHAIN_NAMESPACE, walletClientType:'rabby_wallet', connectorType:'injected', mode:'login-or-sign-up' };
  const res = await http.post(`${PRIVY_BASE}/api/v1/siwe/authenticate`, payload);
  const data = res.data, setCookies = res.headers?.['set-cookie'] || [], bag = {};
  for (const sc of setCookies) { const m = String(sc).match(/^([^=]+)=([^;]+)/); if (m) bag[m[1]] = m[2]; }
  return { data, cookieBag: bag };
}
async function ensureLogin(){
  try { await apiTasks(); return; } catch {}
  const init = await siweInit(address);
  const nonce = init?.nonce || ethers.hexlify(ethers.randomBytes(16)).slice(2);
  const message = buildSiweMessage({
    domain: DOMAIN, uri: NEURAVERSE_ORIGIN, address,
    statement: 'By signing, you are proving you own this wallet and logging in.',
    nonce, chainId: CHAIN_ID_NUM, issuedAt: new Date().toISOString()
  });
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
}

const endpoints = API?.endpoints || {
  infraBase: 'https://neuraverse-testnet.infra.neuraprotocol.io',
  eventsPath: '/api/events',
};
const base = endpoints.infraBase;
const URLS = {
  tasks:        `${base}/api/tasks`,
  claimById:    (id)=> `${base}/api/tasks/${encodeURIComponent(id)}/claim`, 
  claimBulk:    `${base}/api/tasks/claim`,                                  
  leaderboards: `${base}/api/leaderboards`,
  events:       `${base}${endpoints.eventsPath || '/api/events'}`
};

async function apiTasks(){ const { data } = await http.get(URLS.tasks); return data; }
async function apiLeaderboards(){ const { data } = await http.get(URLS.leaderboards); return data; }
async function postEvent(type, payload={}){ try { await http.post(URLS.events, { type, payload }); } catch {} }

async function claimTask(taskId){
  try { 
    const { data } = await http.post(URLS.claimById(taskId), {});
    return { route: 'per-id', data };
  } catch (e) {
    if (e.response?.status && e.response.status !== 404) throw e;
    const { data } = await http.post(URLS.claimBulk, { id: taskId });
    return { route: 'bulk-endpoint', data };
  }
}

const pad = (s,n)=>String(s).padEnd(n,' ');

function printTasksTable(tasks){
  console.log('\n🗒️  Tasks');
  console.log('ID'.padEnd(24), pad('NAME',28), pad('PTS',4), pad('STATUS',12), 'PROGRESS');
  console.log('-'.repeat(80));
  for (const t of tasks) {
    const prog = t?.progress ? `${t.progress.current}/${t.progress.required}` : '-';
    const name = (t.name || '-').length > 27 ? (t.name.slice(0,27)) : t.name || '-';
    console.log(
      pad(t.id,24),
      pad(name,28),
      pad(t.points ?? '-',4),
      pad(t.status ?? '-',12),
      prog
    );
  }
}

function normalizeAddr(v){ try { return ethers.getAddress(v); } catch { return (v||'').toLowerCase(); } }
function pickRowLabel(row){ return row?.address || row?.user || row?.name || row?.id || '—'; }
function pickRowPoints(row){ return row?.points ?? row?.score ?? row?.total ?? row?.value ?? '?'; }

function printLeaderboardCompact(lb){
  console.log('\n🏆 Leaderboard (preview)');
  let top = [];
  let me  = null;
  if (Array.isArray(lb?.top)) { top = lb.top; me = lb.me ?? null; }
  else if (Array.isArray(lb)) { top = lb; }
  else if (Array.isArray(lb?.data)) { top = lb.data; }

  const myAddrNorm = normalizeAddr(address);
  let myRank = null, myPoints = null;

  top.slice(0,25).forEach((row,i)=>{
    const label = pickRowLabel(row);
    const addrNorm = normalizeAddr(label);
    if (addrNorm && addrNorm === myAddrNorm && myRank===null) {
      myRank = i+1; myPoints = pickRowPoints(row);
    }
  });

  if (!myRank && me) {
    const label = pickRowLabel(me);
    myPoints = pickRowPoints(me);
    const addrNorm = normalizeAddr(label);
    if (addrNorm === myAddrNorm) myRank = me.rank || me.position || null;
  }

  if (myRank) console.log(`→ Your rank: #${myRank} (${myPoints})`);
  else console.log('→ Your rank: not in top sample (or format unknown)');
}

(async ()=>{
  try {
    await ensureLogin();
    await postEvent('tasks:visit', {});

    if (!NO_LB) {
      try {
        const lb = await apiLeaderboards();
        printLeaderboardCompact(lb);
      } catch (e) {
        console.log('\n🏆 Leaderboard (preview)');
        console.log('→ Your rank: not available');
      }
    }

    const res = await apiTasks();
    const tasks = Array.isArray(res?.tasks) ? res.tasks : res;
    if (Array.isArray(tasks) && !NO_LIST) {
      printTasksTable(tasks);
    }

    if (!NO_CLAIM && Array.isArray(tasks)) {
      const claimable = tasks.filter(t=> String(t.status).toLowerCase()==='claimable');
      if (!claimable.length) {
        console.log('\n🎯 Tidak ada task claimable saat ini.');
      } else {
        console.log(`\n🎯 Claiming ${claimable.length} task(s)…`);
        for (const t of claimable) {
          try {
            await claimTask(t.id);
            const pts = (t.points != null) ? ` (+${t.points} pts)` : '';
            const desc = t.description ? ` — ${t.description}` : '';
            console.log(`✅ ${t.name}${pts}${desc}`);
          } catch (e) {
            const body = e.response?.data;
            const errMsg = typeof body==='object' ? (body.message || JSON.stringify(body)) : (body || e.message);
            console.log(`❌ ${t.name} — ${errMsg}`);
          }
        }
      }
    }

  } catch (e) {
    if (e?.code === 'BAD_DATA' && /decode/i.test(e.message || '')) {
      console.error('❌ decode error — kemungkinan payload/endpoint klaim beda.');
    } else {
      console.error('[fatal]', e.response?.status || '', e.response?.data ?? e.stack ?? e.message);
    }
    process.exit(1);
  }
})();
