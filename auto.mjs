#!/usr/bin/env node

import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import axios from 'axios';
import { ethers } from 'ethers';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { siweLogin, getPrivateKeys, getProxies } from './auth-core.mjs';

const ROOT = process.cwd();
const CFG_FILE = path.resolve(ROOT, 'config.yaml');
const API_FILE = path.resolve(ROOT, 'api.json');
if (!fs.existsSync(CFG_FILE)) { console.error('Missing config.yaml'); process.exit(1); }
if (!fs.existsSync(API_FILE)) { console.error('Missing api.json'); process.exit(1); }
const CFG = YAML.parse(fs.readFileSync(CFG_FILE,'utf8'));
const API = JSON.parse(fs.readFileSync(API_FILE,'utf8'));

const get = (o,p,d)=>{ try{ return p.split('.').reduce((x,k)=> (x&&k in x)?x[k]:undefined,o) ?? d; }catch{ return d; } };
const sleep = (ms)=> new Promise(r=>setTimeout(r,ms));
const redactMid = (t, keep=6)=>(!t||typeof t!=='string'||t.length<=keep*2)?t:`${t.slice(0,keep)}…${t.slice(-keep)}`;

function agentFromProxy(proxyUrl){
  if(!proxyUrl) return { httpAgent:undefined, httpsAgent:undefined };
  const p = String(proxyUrl).trim().toLowerCase();
  if(p.startsWith('socks')){ const a = new SocksProxyAgent(proxyUrl); return { httpAgent:a, httpsAgent:a }; }
  const a = new HttpsProxyAgent(proxyUrl); return { httpAgent:a, httpsAgent:a };
}
function parseProxy(proxyUrl) {
  if (!proxyUrl) return { enabled: false };
  try {
    const u = new URL(proxyUrl);
    const kind = (u.protocol || '').replace(':','').toLowerCase();
    return { enabled: true, kind, host: u.hostname||'', port: u.port||'', user: u.username||'', pass: u.password||'', raw: proxyUrl };
  } catch {
    const low = String(proxyUrl).toLowerCase();
    const kind = low.startsWith('socks') ? 'socks5' : (low.startsWith('https') ? 'https' : (low.startsWith('http') ? 'http' : 'proxy'));
    return { enabled: true, kind, host: proxyUrl, port: '', user: '', pass: '', raw: proxyUrl };
  }
}
function logSocket(proxyUrl, cfg) {
  const level = String((cfg?.log?.socketLevel ?? 'off')).toLowerCase(); // off | on | all
  const p = parseProxy(proxyUrl);
  if (!p.enabled) { console.log('proxy ❗️off❗️'); return; }
  if (level === 'off') { console.log('proxy ON ✅'); return; }
  if (level === 'on')  { console.log(`✅ Proxy ${(p.kind||'proxy').toUpperCase()} ON ✅`); return; } 
  const auth = (p.user || p.pass) ? `${p.user}:${p.pass}@` : '';
  const hp   = `${p.host}${p.port ? ':'+p.port : ''}`;
  console.log(`✅ ${(p.kind||'proxy').toUpperCase()} ${auth}${hp} ✅`);
}

function makeLogger(cfg) {
  const levelRaw = String(get(cfg,'log.level','silent'));
  const level = levelRaw.toLowerCase(); // 'silent' | 'debugapi' | 'debugall'
  const isSilent   = level === 'silent';
  const isDbgApi   = level === 'debugapi';
  const isDbgAll   = level === 'debugall';
  const show = !isSilent;
  const log = {
    level,
    mini:  (...a)=> console.log(...a),
    info:  (...a)=> show && console.log(...a),
    warn:  (...a)=> console.warn(...a),
    error: (...a)=> console.error(...a),
    api:   (...a)=> (isDbgApi || isDbgAll) && console.log(...a),
    all:   (...a)=> isDbgAll && console.log(...a),
    redactIfNeeded: (s)=> (isDbgAll ? s : redactMid(s)),
  };
  return log;
}

function compactPreview(data, headers, cfg) {
  const max = Number(get(cfg,'log.maxBodyChars',180));
  const elideHtml = Boolean(get(cfg,'log.elideHtml', true));
  const ctype = String(headers?.['content-type']||'').toLowerCase();
  const htmlLike = (v)=> !!v && typeof v==='string' && (v.trimStart().startsWith('<!DOCTYPE') || v.includes('BAILOUT_TO_CLIENT_SIDE_RENDERING'));
  if (elideHtml && (ctype.includes('text/html') || htmlLike(data))) return '[HTML omitted]';
  if (data && typeof data==='object') {
    try { const pick={}; if ('status' in data) pick.status=data.status; if ('message' in data) pick.message=data.message;
      const s = JSON.stringify(Object.keys(pick).length?pick:data); return s.length>max ? s.slice(0,max)+'…' : s; } catch {}
  }
  if (typeof data==='string') return data.length>max ? data.slice(0,max)+'…' : data;
  return String(data ?? '');
}

function normalizeCookies(cookies) {
  if (!cookies) return [];
  if (Array.isArray(cookies)) return cookies.map(s=>String(s).split(';')[0].trim()).filter(Boolean);
  if (typeof cookies === 'string') return cookies.split(';').map(s=>s.trim()).filter(Boolean);
  if (typeof cookies === 'object') return Object.entries(cookies).map(([k,v])=>`${k}=${v}`);
  return [];
}

function httpWithSession({ bearer, cookies, origin, proxy, cfg, log }){
  const agent = agentFromProxy(proxy);
  const inst = axios.create({
    timeout: Number(get(cfg,'net.timeoutMs',45000)),
    headers: {
      accept: 'application/json',
      'content-type':'application/json',
      origin: origin || process.env.NEURAVERSE_ORIGIN || 'https://neuraverse.neuraprotocol.io',
      referer:`${origin || process.env.NEURAVERSE_ORIGIN || 'https://neuraverse.neuraprotocol.io'}/`,
      'privy-app-id': process.env.PRIVY_APP_ID,
      'privy-ca-id' : process.env.PRIVY_CA_ID,
      'privy-client': 'react-auth:2.25.0',
      'user-agent'  : 'Mozilla/5.0 (CLI Privy Bot)',
      ...(bearer ? { authorization : `Bearer ${bearer}` } : {}),
      ...(cookies?.length ? { Cookie: normalizeCookies(cookies).join('; ') } : {}),
    },
    withCredentials: true,
    httpAgent: agent.httpAgent, httpsAgent: agent.httpsAgent,
    proxy:false, validateStatus: ()=>true,
  });

  if (log.level !== 'silent') {
    inst.interceptors.request.use(cfgReq=>{
      cfgReq.meta = { start: Date.now() };
      const h = cfgReq.headers || {};
      const bearerRaw = String(h.authorization||'').replace(/^Bearer\s+/i,'');
      const safeAuth  = bearerRaw ? `Bearer ${log.redactIfNeeded(bearerRaw)}` : undefined;
      const safeCookie= h.Cookie ? (log.level==='debugall' ? h.Cookie : '(set)') : undefined;
      const headersShown = get(CFG,'log.showHeaders', false)
        ? { origin:h.origin,'privy-app-id':h['privy-app-id'],authorization:safeAuth,Cookie:safeCookie }
        : undefined;
      log.api(`⇢ ${String(cfgReq.method||'GET').toUpperCase()} ${cfgReq.url} → ${compactPreview(cfgReq.data, headersShown, cfg)}`);
      if (log.level==='debugall') log.all('[req.headers]', headersShown || h);
      return cfgReq;
    });
    inst.interceptors.response.use(res=>{
      const ms = Date.now() - (res.config.meta?.start || Date.now());
      const headersShown = get(CFG,'log.showHeaders', false) ? res.headers : undefined;
      log.api(`⇠ ${String(res.config.method||'GET').toUpperCase()} ${res.config.url} ${res.status} (${ms}ms) → ${compactPreview(res.data, headersShown, cfg)}`);
      if (log.level==='debugall') log.all('[res.headers]', headersShown || res.headers);
      return res;
    }, err=>{
      const cfgReq = err.config || {};
      const ms = Date.now() - (cfgReq.meta?.start || Date.now());
      const headersShown = get(CFG,'log.showHeaders', false) ? err.response?.headers : undefined;
      log.api(`⇠ ${String(cfgReq.method||'GET').toUpperCase()} ${cfgReq.url} ${err.response?.status||''} (${ms}ms) → ${compactPreview(err.response?.data, headersShown, cfg)}`);
      if (log.level==='debugall') log.all('[err.headers]', headersShown || err.response?.headers);
      return Promise.reject(err);
    });
  }
  return inst;
}

function fileExists(p){ try{ return fs.existsSync(path.resolve(ROOT,p)); }catch{ return false; } }

function getModuleOrder(cfg) {
  const def = ['game','collect','faucet','task','bridge','swap'];
  const fromCfg = Array.isArray(get(cfg,'flow.order', null)) ? get(cfg,'flow.order') : def;
  const disabled = new Set((get(cfg,'flow.disable',[])||[]).map(s=>String(s||'').trim().toLowerCase()));
  return fromCfg.filter(name => !disabled.has(String(name).toLowerCase()));
}

async function runModulesInOrder(ctx){
  const order = getModuleOrder(ctx.config);
  for (const name of order){
    const file = `./${name}.mjs`;
    if (!fileExists(file)) { ctx.log.mini(`- skip: modul "${name}" tidak ditemukan`); continue; }
    try{
      const mod = await import(file);
      if (typeof mod?.run === 'function'){
        ctx.log.mini(`\n▶ ${name}.run()`);
        await mod.run(ctx);
      } else {
        ctx.log.mini(`- skip: modul "${name}" tidak expose run()`);
      }
    }catch(e){
      ctx.log.mini(`❌ ${name}.mjs error: ${e.response?.status || e.message}`);
    }
  }
}

async function loginWithRetry(pk, proxy, log) {
  const tries = Math.max(1, Number(get(CFG,'login.tries', 3)));
  const base  = Math.max(0, Number(get(CFG,'net.baseDelayMs', 300)));
  const back  = Math.max(1, Number(get(CFG,'net.backoff', 1.8)));
  const jitter= Math.max(0, Number(get(CFG,'net.jitterMs', 200)));

  let delay = base;
  for (let t=1; t<=tries; t++){
    try {
      return await siweLogin(pk, {
        proxyUrl: proxy,
        logLevel: get(CFG,'log.level','silent'),
        socketLevel: get(CFG,'log.socketLevel','off')
      });
    } catch (e) {
      const msg = e?.message || String(e);
      if (t === tries) throw e;
      log.mini(`auth retry ${t}/${tries-1} → ${msg}`);
      const jitterMs = Math.floor(Math.random()*jitter);
      await sleep(delay + jitterMs);
      delay = Math.floor(delay*back);
    }
  }
}

(async ()=>{
  try{
    const keys = getPrivateKeys();
    const proxies = getProxies();

    const log = makeLogger(CFG);
    log.mini(`\n🔑 total akun: ${keys.length} | log.level=${log.level}`);

    for (let i=0;i<keys.length;i++){
      const pk    = keys[i];
      const proxy = proxies.length ? proxies[i%proxies.length] : (process.env.PROXY || process.env.SOCKS_PROXY || process.env.HTTPS_PROXY || '');

      const login = await loginWithRetry(pk, proxy, log);

      const bearer  = login.bearer || login.data?.identity_token || login.data?.privy_access_token || login.data?.token;
      const cookies = login.cookies || [];
      const origin  = process.env.NEURAVERSE_ORIGIN || 'https://neuraverse.neuraprotocol.io';

      const http    = httpWithSession({ bearer, cookies, origin, proxy, cfg: CFG, log });

      log.mini(`\n== Account #${i+1} ${login.address} ==`);
      if (log.level!=='silent') {
        console.log('[session] bearer:', log.redactIfNeeded(bearer));
        console.log('[session] cookies set:', (cookies?.length||0));
      }
      logSocket(proxy, CFG);

      const wallet  = new ethers.Wallet(pk);
      const ctx = { address: login.address, wallet, http, env: process.env, config: CFG, api: API, proxy, log, session: { bearer, cookies, origin } };

      await runModulesInOrder(ctx);

      const pause = Number(get(CFG,'flow.betweenAccountsMs', 5000));
      if (i < keys.length-1 && pause>0) { await sleep(pause); }
    }
  }catch(e){
    console.error('[fatal]', e.response?.status || '', e.response?.data ?? e.stack ?? e.message);
    process.exit(1);
  }
})();
