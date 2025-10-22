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
import * as S from './session-store.mjs';
import { makeUI } from './tui.mjs';
import { installNoiseMuter } from './noise-muter.mjs';

const ROOT = process.cwd();
const CFG  = YAML.parse(fs.readFileSync(path.resolve(ROOT,'config.yaml'),'utf8'));
const API  = JSON.parse(fs.readFileSync(path.resolve(ROOT,'api.json'),'utf8'));
const SDB  = S.load();

const get   = (o,p,d)=>{ try{ return p.split('.').reduce((x,k)=> (x&&k in x)?x[k]:undefined,o) ?? d; }catch{ return d; } };
const sleep = (ms)=> new Promise(r=>setTimeout(r,ms));
const redactMid = (t, keep=6)=>(!t||typeof t!=='string'||t.length<=keep*2)?t:`${t.slice(0,keep)}…${t.slice(-keep)}`;
const shortAddr = (a)=> a ? (a.slice(0,6)+'…'+a.slice(-4)) : '0x??';
const fmtLeft = (ms)=>{ if(!ms||ms<=0) return 'expired'; const s=Math.floor(ms/1000); if(s<60)return`${s}s`; const m=Math.floor(s/60); if(m<60)return`${m}m`; const h=Math.floor(m/60); const mm=m%60; return `${h}h${mm?mm+'m':''}`; };

/* === socks5 -> socks5h normalizer (DNS lewat proxy) === */
function normalizeProxyUrl(u) {
  if (!u) return u;
  try {
    const url = new URL(u);
    if (url.protocol === 'socks5:') url.protocol = 'socks5h:';
    return url.toString();
  } catch {
    const s = String(u);
    return s.startsWith('socks5://') ? s.replace(/^socks5:\/\//,'socks5h://') : s;
  }
}

function agentFromProxy(proxyUrl){
  if(!proxyUrl) return {httpAgent:undefined,httpsAgent:undefined};
  const raw = normalizeProxyUrl(proxyUrl);
  const p=String(raw).trim().toLowerCase();
  if(p.startsWith('socks')){const a=new SocksProxyAgent(raw);return{httpAgent:a,httpsAgent:a};}
  const a=new HttpsProxyAgent(raw); return {httpAgent:a,httpsAgent:a};
}
function parseProxy(proxyUrl){
  if(!proxyUrl)return{enabled:false};
  try{
    const norm = normalizeProxyUrl(proxyUrl);
    const u=new URL(norm);
    const kind=(u.protocol||'').replace(':','').toLowerCase();
    return{enabled:true,kind,host:u.hostname||'',port:u.port||'',user:u.username||'',pass:u.password||'',raw:norm};
  }catch{
    const raw = normalizeProxyUrl(String(proxyUrl));
    const low=raw.toLowerCase();
    const kind=low.startsWith('socks5h')?'socks5h':(low.startsWith('socks')?'socks5':(low.startsWith('https')?'https':(low.startsWith('http')?'http':'proxy')));
    return{enabled:true,kind,host:raw,port:'',user:'',pass:'',raw};
  }
}
function logSocket(proxyUrl, ui){
  const level=String(get(CFG,'log.socketLevel','off')).toLowerCase();
  const p=parseProxy(proxyUrl);
  if(!p.enabled){ ui?.session?.('proxy ❗️off❗️'); return; }
  if(level==='off'){ ui?.session?.('proxy ON ✅'); return; }
  if(level==='on'){ ui?.session?.(`✅ Proxy ${(p.kind||'proxy').toUpperCase()} ON ✅`); return; }
  const auth=(p.user||p.pass)?`${p.user}:${p.pass}@`:''; const hp=`${p.host}${p.port?':'+p.port:''}`;
  ui?.session?.(`✅ ${(p.kind||'proxy').toUpperCase()} ${auth}${hp} ✅`);
}

function makeLogger(){
  const level=String(get(CFG,'log.level','silent')).toLowerCase();
  const show=level!=='silent';
  return {
    level,
    mini:(...a)=>console.log(...a),
    info:(...a)=> show&&console.log(...a),
    warn:(...a)=>console.warn(...a),
    error:(...a)=>console.error(...a),
    api:(...a)=>(level==='debugapi'||level==='debugall')&&console.log(...a),
    all:(...a)=> (level==='debugall')&&console.log(...a),
    redactIfNeeded:(s)=> (level==='debugall'?s:redactMid(s))
  };
}

function toCookieArray(set){ const arr=Array.isArray(set)?set:(set?[set]:[]); return arr.map(s=> String(s).split(';')[0].trim()).filter(Boolean); }
function parseJwtExp(tok){ try{const[,p]=String(tok||'').split('.'); if(!p)return 0; const json=JSON.parse(Buffer.from(p.replace(/-/g,'+').replace(/_/g,'/'),'base64').toString()); return Number(json.exp||0)*1000;}catch{return 0;} }
function updateSessionFromResponse(res, ctx){
  try{
    const set=res?.headers?.['set-cookie'];
    if(set){
      const newKV=toCookieArray(set);
      if(newKV.length){
        const cur=new Set(ctx.session.cookies||[]);
        newKV.forEach(c=>cur.add(c));
        ctx.session.cookies=Array.from(cur);
        ctx.http.defaults.headers.Cookie=ctx.session.cookies.join('; ');
      }
    }
    const nb=res?.data?.identity_token || res?.data?.privy_access_token || res?.data?.token;
    if(nb){
      ctx.session.bearer=nb;
      ctx.session.expiresAt=parseJwtExp(nb);
      ctx.http.defaults.headers.authorization=`Bearer ${nb}`;
    }
  }catch{}
}

function httpWithSession({ bearer, cookies, origin, proxy }){
  const agent=agentFromProxy(proxy);
  const inst=axios.create({
    timeout: Number(get(CFG,'net.timeoutMs',45000)),
    headers: {
      accept:'application/json','content-type':'application/json',
      origin: origin || process.env.NEURAVERSE_ORIGIN, referer:`${origin||process.env.NEURAVERSE_ORIGIN}/`,
      'privy-app-id':process.env.PRIVY_APP_ID,'privy-ca-id':process.env.PRIVY_CA_ID,'privy-client':'react-auth:2.25.0',
      'user-agent':'Mozilla/5.0 (CLI Privy Bot)',
      ...(bearer?{authorization:`Bearer ${bearer}`}:{}) , ...(cookies?.length?{Cookie:cookies.join('; ')}:{})
    },
    withCredentials:true, httpAgent:agent.httpAgent, httpsAgent:agent.httpsAgent,
    proxy:false, validateStatus:()=>true
  });
  return inst;
}

// ========= compactors (ringkasan log panel) =========
const SHORT = h => String(h||'').slice(0,10)+'…';
const taskStateByPanel = new Map();
const _taskKey = (p,slot)=> `${p}|${slot||''}`;

function summarizeTask(lines){
  const claim=lines.filter(l=>/\bclaimable\b/i.test(l)).length;
  const claimed=lines.filter(l=>/\bclaimed\b/i.test(l)).length;
  const open=lines.filter(l=>/\bnotCompleted\b/i.test(l)).length;
  return `[tasks] summary: claimable=${claim}, claimed=${claimed}, open=${open}`;
}
function isTaskEnd(s){
  return /^No claimable tasks\./i.test(s) || /^tasks\s*→/i.test(s) ||
    /^(pulse#|visit |🎉 |▶ |- skip|neuraPoints|🪙|wrap|retry|swap:|bridge|faucet|multi|batch|idle)/i.test(s);
}
function compactTaskLine(raw,panel,slot){
  const s=String(raw); const key=_taskKey(panel,slot); const st=taskStateByPanel.get(key)||{active:false,lines:[]};
  if (/^🗒️\s*Tasks/i.test(s)){ st.active=true; st.lines=[]; taskStateByPanel.set(key,st); return null; }
  if (st.active){
    if (isTaskEnd(s)){ const out=summarizeTask(st.lines); st.active=false; st.lines=[]; taskStateByPanel.set(key,st); return out; }
    st.lines.push(s); taskStateByPanel.set(key,st); return null;
  }
  const m = s.match(/^claim\s+([a-z0-9_:-]+)\s*→\s*(\d+)/i);
  if(m) return `[tasks] claim ${m[1]} ✅ (${m[2]})`;
  return undefined;
}
function compactSwapLine(s){
  if (/\bnative<=minFee\b/i.test(s)) return '[wrap] skip (native<=minFee)';
  let m = s.match(/\[wrap\]\s*tx:\s*(0x[0-9a-f]{64})/i); if(m) return `[wrap] tx ${SHORT(m[1])}`;
  m = s.match(/\[swap:([a-z0-9]+\/[a-z0-9]+)\]\s*tx:\s*(0x[0-9a-f]{64})/i); if(m) return `[swap:${m[1]}] tx ${SHORT(m[2])}`;
  m = s.match(/\[swap:([a-z0-9]+\/[a-z0-9]+)\].*?✅.*block\s+(\d+)/i); if(m) return `[swap:${m[1]}] ✅ block ${m[2]}`;
  m = s.match(/\[multi\].*?route\s+"([^"]+)".*?\(tx=(0x[0-9a-f]{64})\)/i); if(m) return `[multi] ✅ ${m[1]} · ${SHORT(m[2])}`;
  m = s.match(/\[retry:([a-z0-9]+\/[a-z0-9]+)\].*attempt[s= ]?=*(\d+).*delay=([0-9]+)ms/i); if(m) return `[retry:${m[1]}] attempts=${m[2]} delay=${m[3]}ms`;
  m = s.match(/\[retry:([a-z0-9]+\/[a-z0-9]+)\]\s*(\d+)\/(\d+).*reverted/i); if(m) return `[retry:${m[1]}] ${m[2]}/${m[3]} · reverted`;
  return null;
}
function compactGeneralLine(s){
  if (/JsonRpcProvider failed to detect network/i.test(s)) return null;
  if (/could not coalesce/i.test(s)) return null;
  if (/POST\s+\/api\/faucet\s+404/.test(s)) return null;
  if (/POST\s+\/api\/faucet\s+400/.test(s) && /Wallet address is/i.test(s)) return null;
  if (/POST\s+\/api\/faucet\s+403/.test(s)) return 'faucet: access denied';
  if (/faucet:\s*tidak ada endpoint/i.test(s)) return 'faucet: no endpoint';
  if (/^\[?autoback\]?/i.test(s)) return null;
  if (/useRouter="/i.test(s) || /schedule=/.test(s)) return null;
  // if (/^visit\s+/i.test(s)) return null;
  if (/^▶\s+grouped:/i.test(s)) return null;
  if (/^•\s+\w+\.run\(\)/i.test(s)) return null;
  if (/^No claimable tasks\./i.test(s) || /^tasks\s*→/i.test(s)) return null;
  if (/^🪙\s*faucet\.run\(\)/i.test(s) || /^neuraPoints/i.test(s)) return null;
  let m = s.match(/pulse#\s*(\d+).*pulse:collectPulse\(id\).*→\s*200/i); if(m) return `[pulse] #${m[1]} ✅`;
  if (/pulse:collectPulse.*→\s*400/i.test(s)) return null;
  if (/ECONNRESET/i.test(s)) return '⚠️ net reset';
  return s;
}
function makePaneLogger(baseLog, ui, panel, slotTag){
  if (!ui?.enabled) return baseLog;
  const lvl = baseLog.level, show = lvl!=='silent';
  const strict = Boolean(get(CFG,'ui.strictCompact', true));
  const TRUNC = Math.max(20, Number(get(CFG,'ui.truncateWidth', 90)));
  const emit = (out)=>{
    if (!out && strict) return; if (!out) return;
    let flat = String(out).replace(/\x1b\[[0-9;]*m/g,'').replace(/\r?\n|\r/g,' ')
      .replace(/[\u0000-\u001F\u007F]/g,'').replace(/\s{2,}/g,' ').trim();
    const line = flat.length>TRUNC ? (flat.slice(0,TRUNC-1)+'…') : flat;
    ui.write(panel, line, slotTag);
  };
  const writeCompact = (line)=>{
    const t = compactTaskLine(line, panel, slotTag);
    if (t === null) return;
    if (typeof t === 'string') return emit(t);
    if (/\[(swap|wrap|retry|multi)\:|\[wrap\]/i.test(line)) {
      const c = compactSwapLine(line); return emit(c || (strict?null:line));
    }
    return emit(compactGeneralLine(line));
  };
  const join = a => a.map(x=> typeof x==='string'? x : JSON.stringify(x)).join(' ');
  return {
    ...baseLog,
    mini: (...a)=> writeCompact(join(a)),
    info: (...a)=> show && writeCompact(join(a)),
    warn:  (...a)=> writeCompact('⚠️ '+join(a)),
    error: (...a)=> writeCompact('❌ '+join(a)),
    api:   (...a)=> (lvl==='debugapi'||lvl==='debugall') && writeCompact(join(a)),
    all:   (...a)=> (lvl==='debugall') && writeCompact(join(a)),
    redactIfNeeded: baseLog.redactIfNeeded
  };
}

function fileExists(p){ try{ return fs.existsSync(path.resolve(ROOT,p)); }catch{ return false; } }
function getModuleOrder(cfg){
  const def=['game','collect','faucet','task','bridge','swap'];
  const fromCfg=Array.isArray(get(cfg,'flow.order',null))?get(cfg,'flow.order'):def;
  const disabled=new Set((get(cfg,'flow.disable',[])||[]).map(s=>String(s||'').trim().toLowerCase()));
  return fromCfg.filter(n=>!disabled.has(String(n).toLowerCase()));
}
async function runModulesInOrder(ctx){
  const order=getModuleOrder(ctx.config);
  for(const name of order){
    const file=`./${name}.mjs`;
    if(!fileExists(file)){ ctx.log.mini(`- skip: modul "${name}" tidak ditemukan`); continue; }
    try{
      const mod=await import(file);
      if(typeof mod?.run==='function'){ ctx.log.mini(`▶ ${name}.run()`); await mod.run(ctx);}
      else { ctx.log.mini(`- skip: modul "${name}" tidak expose run()`);}
    }catch(e){
      ctx.log.mini(`❌ ${name}.mjs error: ${e.response?.status || e.message}`);
    }
  }
}
function pLimit(conc){
  let active=0; const q=[];
  const next=()=>{ if(active>=conc || !q.length) return;
    active++; const {fn,resolve,reject}=q.shift();
    Promise.resolve().then(fn).then(v=>{active--;resolve(v);next();},
      e=>{active--;reject(e);next();});
  };
  return (fn)=> new Promise((res,rej)=>{ q.push({fn,resolve:res,reject:rej}); next(); });
}
async function runModulesGrouped(ctx){
  const mode=String(get(ctx.config,'flow.mode','serial')).toLowerCase();
  if(mode!=='grouped') return runModulesInOrder(ctx);
  const all = getModuleOrder(ctx.config);
  const defGroups=[['game','collect','task'],['faucet'],['bridge'],['swap']];
  const groups=(Array.isArray(get(ctx.config,'flow.parallelGroups',null))&&get(ctx.config,'flow.parallelGroups',null).length)?get(ctx.config,'flow.parallelGroups',null):defGroups;
  const present=new Set(all.map(x=>String(x)));
  const plan=groups.map(g=>g.filter(n=>present.has(n))).filter(g=>g.length);
  const perMax=Math.max(1, Number(get(ctx.config,'flow.perAccountMax',2)));
  const limit=pLimit(perMax);
  for(const group of plan){
    ctx.log.mini(`▶ grouped: [${group.join(', ')}] (max ${perMax})`);
    const tasks=group.map(name=> limit(async ()=>{
      const file=`./${name}.mjs`;
      if(!fileExists(file)){ ctx.log.mini(`- skip: modul "${name}" tidak ditemukan`); return; }
      try{
        const mod=await import(file);
        if(typeof mod?.run==='function'){ ctx.log.mini(`• ${name}.run()`); await mod.run(ctx); }
        else { ctx.log.mini(`- skip: modul "${name}" tidak expose run()`);}
      }catch(e){ ctx.log.mini(`❌ ${name}.mjs error: ${e.response?.status || e.message}`); }
    }));
    await Promise.allSettled(tasks);
  }
}

/* ================== AUTH LAYER (PATCHED) ================== */

/** Circuit breaker state untuk relogin/hardReauth */
const authCB = new Map(); // address -> { fails, until }
function cbGet(a){ return authCB.get(a) || { fails:0, until:0 }; }
function cbBlock(a){ const s = cbGet(a); return s.until > Date.now(); }
function cbFail(a){
  const s = cbGet(a);
  s.fails = (s.fails||0) + 1;
  if (s.fails >= Number(get(CFG,'authGuard.maxFails', 3))) {
    s.until = Date.now() + Number(get(CFG,'authGuard.coolOffMs', 30*60*1000));
  }
  authCB.set(a, s);
}
function cbOk(a){ authCB.set(a, { fails:0, until:0 }); }

/** 401 interceptor “cerdas”: soft → hard → give up (sekali siklus) */
function install401Replay(ctx){
  let inFlight401 = false;

  ctx.http.interceptors.response.use(async (res)=>{
    updateSessionFromResponse(res, ctx);
    if (res.status !== 401) return res;

    if (inFlight401) return res; // hindari recursive loop
    inFlight401 = true;

    // 1) coba soft refresh
    await ensureFreshAuth(ctx, '401');
    if (ctx.session?.bearer) {
      inFlight401 = false;
      return await ctx.http.request(res.config);
    }

    // 2) soft gagal → hard reauth
    await hardReauth(ctx, '401-hard');
    inFlight401 = false;

    if (ctx.session?.bearer) {
      return await ctx.http.request(res.config);
    } else {
      // 3) menyerah sementara (biar modul & loop berikutnya yang lanjut)
      ctx.ui.session?.(`401 persist · give up · ${shortAddr(ctx.address)}`);
      return res;
    }
  }, e=>Promise.reject(e));
}

/** Soft refresh (SIWE ringan) */
async function ensureFreshAuth(ctx, reason=''){
  if (ctx._authLock) return ctx._authLock;
  if (cbBlock(ctx.address)) {
    ctx.ui.session?.(`relogin blocked (cooldown) · ${shortAddr(ctx.address)}`);
    return;
  }

  const historyMapFile = get(CFG,'auth.historyMapFile','history.json');
  const historyMapUsed = (fs.existsSync(path.resolve(ROOT, historyMapFile))) ? historyMapFile : null;

  ctx._authLock = (async ()=>{
    try{
      const relog = await siweLogin(ctx.wallet.privateKey, {
        proxyUrl: ctx.proxy,
        logLevel: ctx.log.level,
        socketLevel: 'off',
        forceNew: /401|pre-exp|idle-keepalive/i.test(reason) ? true : false,
        ...(historyMapUsed ? { historyMapFile: historyMapUsed } : {})
      });

      const nb = relog.bearer || relog.data?.identity_token || relog.data?.privy_access_token || relog.data?.token;
      if (!nb) throw new Error('no bearer from siweLogin');

      ctx.session.bearer   = nb;
      ctx.session.cookies  = relog.cookies || ctx.session.cookies || [];
      ctx.session.expiresAt= parseJwtExp(nb);
      ctx.http.defaults.headers.authorization = `Bearer ${nb}`;
      if ((ctx.session.cookies||[]).length) ctx.http.defaults.headers.Cookie = ctx.session.cookies.join('; ');

      ctx.stats.reloginOK++; globalStats.reloginOK++;
      cbOk(ctx.address);
      ctx.ui.session?.(`relogin OK (${reason}) · ${shortAddr(ctx.address)} · in ${fmtLeft(ctx.session.expiresAt - Date.now())}`);
      ctx._persist?.();

    }catch(e){
      ctx.stats.reloginFail++; globalStats.reloginFail++;
      cbFail(ctx.address);
      ctx.ui.session?.(`relogin FAIL · ${shortAddr(ctx.address)} · ${e.message||e}`);
    }
  })().finally(()=>{ ctx._authLock = null; });

  return ctx._authLock;
}

/** Hard reauth: paksa login penuh + rotate proxy + (opsional) solver eksternal */
async function hardReauth(ctx, reason=''){
  if (cbBlock(ctx.address)) {
    ctx.ui.session?.(`hardReauth blocked (cooldown) · ${shortAddr(ctx.address)}`);
    return;
  }

  const proxiesRaw = getProxies().map(normalizeProxyUrl);
  const list = proxiesRaw.length ? proxiesRaw : [ctx.proxy || ''];
  const maxSwitch = Math.min(Number(get(CFG,'auth.maxProxySwitches', 5)), Math.max(0, list.length-1));
  let lastErr = null;

  for (let i=0; i<=maxSwitch; i++){
    const proxy = list[(i) % list.length];
    logSocket(proxy, ctx.ui);

    try{
      // bersihkan state lama agar benar2 fresh
      ctx.session.cookies = [];
      ctx.session.bearer  = '';
      ctx.session.expiresAt = 0;
      ctx.http.defaults.headers.authorization = '';
      delete ctx.http.defaults.headers.Cookie;

      // OPTIONAL solver captcha/turnstile (sesuaikan kalau kamu punya script)
      // if (get(CFG,'auth.hard.solveViaNode', false)) {
      //   await runExternalSolverOnce();
      // }

      const res = await siweLogin(ctx.wallet.privateKey, {
        proxyUrl: proxy,
        logLevel: ctx.log.level,
        socketLevel: 'off',
        forceNew: true,
        freshDevice: true,
        clearCookies: true,
      });

      const nb = res.bearer || res.data?.identity_token || res.data?.privy_access_token || res.data?.token;
      if (!nb) throw new Error('no bearer from hard reauth');

      ctx.session.bearer   = nb;
      ctx.session.cookies  = res.cookies || [];
      ctx.session.expiresAt= parseJwtExp(nb);
      ctx.http.defaults.headers.authorization = `Bearer ${nb}`;
      if ((ctx.session.cookies||[]).length) ctx.http.defaults.headers.Cookie = ctx.session.cookies.join('; ');

      globalStats.loginOK++; cbOk(ctx.address);
      ctx.ui.session?.(`hardReauth OK (${reason}) · ${shortAddr(ctx.address)} · proxy#${i+1}`);
      ctx._persist?.();
      return;

    }catch(e){
      lastErr = e;
      cbFail(ctx.address);
      ctx.ui.session?.(`hardReauth FAIL · ${shortAddr(ctx.address)} · ${e.message||e}`);
      if (i < maxSwitch) ctx.ui.session?.('switch proxy → next');
    }
  }

  // gagal semua
  globalStats.loginFail++;
  ctx.ui.session?.(`hardReauth give up · ${shortAddr(ctx.address)} · last=${lastErr?.message||lastErr}`);
}

/* ============== end AUTH LAYER (PATCHED) ============== */

async function bootstrapPrivySession(ctx){ ctx.ui.session?.(`bootstrap skip · ${shortAddr(ctx.address)}`); return 204; }

const globalStats = { loginOK:0, loginFail:0, reloginOK:0, reloginFail:0, batchesDone:0, total:0, batchNow:0, batchTotal:0 };
function sidebarRender(ui){
  const L=[];
  L.push('TOTAL ACCOUNTS: '+globalStats.total);
  L.push(`LOGIN  : OK ${globalStats.loginOK} · FAIL ${globalStats.loginFail}`);
  L.push(`RELOGIN: OK ${globalStats.reloginOK} · FAIL ${globalStats.reloginFail}`);
  if (globalStats.batchTotal) L.push(`BATCH  : ${globalStats.batchNow}/${globalStats.batchTotal}`);
  L.push('BATCHES: '+globalStats.batchesDone);
  ui.sidebarSet?.(L);
}

/* ==== LOGIN + ROTASI PROXY ==== */
let _nextLoginAt = 0;

/** Coba login dengan retry di satu proxy */
async function tryLoginOnceProxy(pk, proxy, ui, historyArg){
  const tries  = Math.max(1, Number(get(CFG,'auth.perProxyTries', 2)));
  let   delay  = Number(get(CFG,'auth.rateBaseMs', 4000));
  const back   = Number(get(CFG,'auth.rateBackoff', 1.8));
  const jitter = Number(get(CFG,'auth.rateJitterMs', 500));

  for (let t=1; t<=tries; t++){
    try{
      const res = await siweLogin(pk, {
        proxyUrl: proxy,
        logLevel: get(CFG,'log.level','silent'),
        socketLevel: get(CFG,'log.socketLevel','off'),
        ...historyArg
      });
      return res;
    }catch(e){
      const msg = e?.message||'';
      const transient = /(?:\b401\b|\b403\b|429|too[_\s-]*many|ECONNRESET|ETIMEDOUT|ENETUNREACH|EAI_AGAIN|timeout|before secure TLS connection|siwe\.init\s+401)/i.test(msg);
      if (t<tries && transient){
        const w = delay + Math.floor(Math.random()*jitter);
        ui.session?.(`login retry ${t}/${tries} @proxy → wait ${w}ms`);
        await sleep(w); delay = Math.floor(delay*back); continue;
      }
      throw e;
    }
  }
}

/** Login throttled + rotasi proxy kalau gagal */
async function loginThrottledRotate(pk, proxiesList, startIdx, ui) {
  const minGap = Number(get(CFG,'auth.minGapMs', 9000));

  // history map (opsional)
  const historyMapFile = get(CFG,'auth.historyMapFile','history.json');
  const pathAbs = path.resolve(ROOT, historyMapFile);
  const historyMapExists = fs.existsSync(pathAbs);
  const historyMap = historyMapExists ? JSON.parse(fs.readFileSync(pathAbs,'utf8')) : null;
  const historyArg = historyMap ? { historyMap } : (historyMapExists ? { historyMapFile } : {});

  // throttle global
  const wait = Math.max(0, _nextLoginAt - Date.now());
  if (wait>0) ui.session?.(`login throttle ${wait}ms`);
  if (wait>0) await sleep(wait);

  // siapkan daftar proxy yang akan dicoba
  const envProxy = normalizeProxyUrl(process.env.PROXY || process.env.SOCKS_PROXY || process.env.HTTPS_PROXY || '');
  const list = (proxiesList && proxiesList.length) ? proxiesList.slice() : (envProxy ? [envProxy] : []);
  if (!list.length) list.push(''); // kosong = direct

  const maxSwitches = Math.min(
    Number(get(CFG,'auth.maxProxySwitches', 999)),
    list.length - 1 >= 0 ? list.length - 1 : 0
  );

  let lastErr = null;
  for (let sw = 0; sw <= maxSwitches; sw++){
    const idx = ( (startIdx||0) + sw ) % list.length;
    const proxy = list[idx];
    logSocket(proxy, ui);

    try{
      const res = await tryLoginOnceProxy(pk, proxy, ui, historyArg);
      _nextLoginAt = Date.now() + minGap;
      globalStats.loginOK++; sidebarRender(ui);
      return { login: res, proxyUsed: proxy };
    }catch(e){
      lastErr = e;
      ui.session?.(`login FAIL @proxy#${idx+1}/${list.length} · ${e.message||e}`);
      if (sw < maxSwitches) {
        ui.session?.(`switch proxy → next`);
      }
    }
  }

  globalStats.loginFail++; sidebarRender(ui);
  throw lastErr || new Error('login failed after proxy rotation');
}

/* ===== keepAlive helpers ===== */
async function keepAliveTick(ctx){
  try{
    // refresh kalau sisa token < renewSkewMs
    const skew = Number(get(CFG,'keepAlive.renewSkewMs', 15 * 60 * 1000));
    const left = (ctx.session.expiresAt || 0) - Date.now();
    if (skew > 0 && left < skew){
      await ensureFreshAuth(ctx, 'idle-keepalive');
      ctx._persist?.();
    }

    // ping opsional
    if (get(CFG,'keepAlive.ping.enabled', false)){
      const url = get(CFG, 'keepAlive.ping.url', ctx.session.origin || process.env.NEURAVERSE_ORIGIN);
      const r = await ctx.http.get(url, { validateStatus:()=>true });
      ctx.log.mini(`[ping] ${shortAddr(ctx.address)} → ${r.status}`);
    }
  }catch(e){
    ctx.log.mini(`[ping] fail ${shortAddr(ctx.address)}: ${e.response?.status || e.code || e.message}`);
  }
}

async function buildAccountCtx({ pk, proxies, proxyStartIdx, baseLog, ui, i }) {
  const wallet = new ethers.Wallet(pk);
  const { panel, slot } = ui.assignAccount(i, shortAddr(wallet.address));
  const log = makePaneLogger(baseLog, ui, panel, `#${i+1}`);

  let bearer, cookies, login, proxyUsed;
  const cached = S.getFor(SDB, wallet.address);
  // gunakan renewSkewMs dari config
  const renewSkewMs = Number(get(CFG,'keepAlive.renewSkewMs', 6 * 60 * 60 * 1000));

  if (cached && cached.bearer && Array.isArray(cached.cookies)) {
    const left = (cached.expiresAt || 0) - Date.now();
    if (left > renewSkewMs) {
      bearer  = cached.bearer; cookies = cached.cookies; login = { address: wallet.address }; proxyUsed = proxies?.[proxyStartIdx] || (process.env.PROXY || process.env.SOCKS_PROXY || process.env.HTTPS_PROXY || '');
      ui.session?.(`INIT reuse · ${shortAddr(wallet.address)} · expires in ${fmtLeft(left)}`);
    } else {
      ui.session?.(`INIT cached near-exp (${fmtLeft(left)}) → relogin · ${shortAddr(wallet.address)}`);
      const out = await loginThrottledRotate(pk, proxies, proxyStartIdx, ui);
      login = out.login; proxyUsed = out.proxyUsed;
      ui.session?.(`login OK · ${shortAddr(wallet.address)} · cookies=${(login.cookies||[]).length}`);
      bearer  = login.bearer || login.data?.identity_token || login.data?.privy_access_token || login.data?.token;
      cookies = login.cookies || [];
    }
  } else {
    ui.session?.(`INIT need-login · ${shortAddr(wallet.address)}`);
    const out = await loginThrottledRotate(pk, proxies, proxyStartIdx, ui);
    login = out.login; proxyUsed = out.proxyUsed;
    ui.session?.(`login OK · ${shortAddr(wallet.address)} · cookies=${(login.cookies||[]).length}`);
    bearer  = login.bearer || login.data?.identity_token || login.data?.privy_access_token || login.data?.token;
    cookies = login.cookies || [];
  }

  const origin  = process.env.NEURAVERSE_ORIGIN || 'https://neuraverse.neuraprotocol.io';
  const http    = httpWithSession({ bearer, cookies, origin, proxy: proxyUsed });

  const ctx = {
    address: (login?.address) || wallet.address,
    wallet, http, env: process.env, config: CFG, api: API, proxy: proxyUsed, log, ui,
    stats: { reloginOK:0, reloginFail:0 },
    session: { bearer, cookies, origin, expiresAt: bearer ? parseJwtExp(bearer) : 0 },
    _authLock:null,
    _persist: ()=> S.save(S.putFor(SDB, ((login?.address)||wallet.address), {
      bearer: ctx.session.bearer, cookies: ctx.session.cookies, origin: ctx.session.origin, expiresAt: ctx.session.expiresAt
    }))
  };
  install401Replay(ctx);
  await bootstrapPrivySession(ctx);
  ctx._persist();

  // Scheduler per-akun untuk early renew (tetap ada)
  const renewSkew = Number(get(CFG,'keepAlive.renewSkewMs', 15 * 60 * 1000));
  const checkMs   = Number(get(CFG,'authGuard.checkMs', 120000));
  const jitter    = Number(get(CFG,'authGuard.jitterMs', 15000));
  setTimeout(async function loop(){
    try{
      const left = ctx.session.expiresAt - Date.now();
      if (renewSkew>0 && left < renewSkew){ await ensureFreshAuth(ctx, 'pre-exp'); ctx._persist?.(); }
    }finally{
      const j = Math.floor((Math.random()*2-1)*jitter);
      setTimeout(loop, Math.max(30_000, checkMs + j));
    }
  }, 500);

  return ctx;
}

const status = new Map();
async function runAccountCycle(ctx){
  const st = status.get(ctx.address) || { busy:false };
  if (st.busy) return;
  st.busy = true; status.set(ctx.address, st);
  try{ await runModulesGrouped(ctx); st.lastOk=Date.now(); }
  catch(e){ st.lastErr=Date.now(); ctx.log.warn(`[acct] error ${ctx.address}:`, e.message||e); }
  finally{ st.busy=false; status.set(ctx.address, st); }
}
async function runRound(contexts, baseLog){
  const MAX = Number(get(CFG,'flow.maxConcurrency', 3));
  const q = [...contexts];
  while (q.length){
    const batch = q.splice(0, MAX);
    await Promise.all(batch.map(runAccountCycle));
  }
  baseLog.api?.(`[round] done (batch=${MAX})`);
}

async function runModulesListOnAll(contexts, modules, concurrency=3, delayBetweenModulesMs=0){
  const names = Array.isArray(modules) ? modules : [];
  if (!names.length || !contexts.length) return;
  const limit = pLimit(Math.max(1, Number(concurrency)));
  for (const modName of names) {
    const file = `./${modName}.mjs`;
    if (!fs.existsSync(path.resolve(process.cwd(), file))) continue;
    const mod = await import(file);
    await Promise.all(contexts.map(ctx => limit(async () => {
      try { await mod.run(ctx); }
      catch (e) { ctx.log.mini(`❌ ${modName}.run: ${e.message || e}`); }
    })));
    if (delayBetweenModulesMs>0) await sleep(delayBetweenModulesMs);
  }
}

function startSessionTicker(allCtx, ui){
  const ms = Math.max(10_000, Number(get(CFG,'ui.sessionTickMs', 30_000)));
  const render = ()=>{
    const lines = ['ACCOUNTS · status summary'];
    for (let i=0;i<allCtx.length;i++){
      const c = allCtx[i]; if (!c) continue;
      const left = (c.session.expiresAt||0) - Date.now();
      const state = c._authLock ? 'refreshing' : 'ok';
      lines.push(`[${i+1}] ${shortAddr(c.address)} | exp in ${fmtLeft(left)} | ${state} | cookies=${(c.session.cookies||[]).length}`);
    }
    ui.sessionSet?.(lines);
  };
  setInterval(render, ms); render();
}

(async ()=>{
  try{
    const keysRaw = getPrivateKeys();
    const proxiesRaw = getProxies();
    const proxies = proxiesRaw.map(normalizeProxyUrl);
    const baseLog = makeLogger();
    const ui = makeUI(CFG);
    if (ui._initPromise) await ui._initPromise;

    installNoiseMuter(ui);

    globalStats.total = keysRaw.length;
    ui.session?.(`🔑 total akun: ${keysRaw.length} | log.level=${baseLog.level}`);
    let batchSize = Number(get(CFG,'flow.loginBatchSize', get(CFG,'flow.perAccountMax', 3)));
    if (!batchSize || batchSize<1) batchSize = 3;
    globalStats.batchTotal = Math.ceil(keysRaw.length / batchSize);
    let batchIdx = 0;
    const contextsAll = [];

    const loginConc    = Math.max(1, Number(get(CFG,'auth.loginConcurrency', 1)));
    const loginStagger = Math.max(0, Number(get(CFG,'auth.loginStaggerMs', 1200)));
    const haveMultiProxy = proxies.length > 1;
    const limitLogin = pLimit(haveMultiProxy ? loginConc : 1);

    for (let start=0; start<keysRaw.length; start += batchSize) {
      const end = Math.min(keysRaw.length, start + batchSize);
      batchIdx++; globalStats.batchNow = batchIdx; sidebarRender(ui);
      ui.session?.(`📦 Batch ${batchIdx}/${globalStats.batchTotal}: akun ${start+1}..${end}`);

      const results = await Promise.all(keysRaw.slice(start, end).map((pk, idx)=>{
        const i = start + idx;
        const startIdx = proxies.length ? (i % proxies.length) : 0;
        return limitLogin(async ()=>{
          if (loginStagger>0){ const jitter = Math.floor(Math.random()*loginStagger); await sleep(loginStagger + jitter); }
          try {
            const ctx = await buildAccountCtx({ pk, proxies, proxyStartIdx:startIdx, baseLog, ui, i });
            return {ok:true, ctx};
          } catch (e) {
            ui.session?.(`login FAIL · ${shortAddr(new ethers.Wallet(pk).address)} · ${e.message||e}`);
            return {ok:false};
          }
        });
      }));

      const okCtx = results.filter(x=>x.ok).map(x=>x.ctx);
      if (okCtx.length){ await runRound(okCtx, baseLog); contextsAll.push(...okCtx); }
      globalStats.batchesDone++; sidebarRender(ui);

      const between = Number(get(CFG,'flow.betweenBatchesMs', 4000));
      if (between>0 && end<keysRaw.length) { ui.session?.(`[batch] jeda ${between}ms`); await sleep(between); }
    }

    const aft = (CFG.flow && CFG.flow.afterAll) || {};
    if (aft.enabled !== false && Array.isArray(aft.modules) && aft.modules.length) {
      const rounds = Math.max(1, Number(aft.rounds || 1));
      const conc   = Math.max(1, Number(aft.concurrency || 3));
      const dMod   = Math.max(0, Number(aft.delayBetweenModulesMs || 0));
      const dRnd   = Math.max(0, Number(aft.delayBetweenRoundsMs || 0));
      for (let r=1; r<=rounds; r++){
        ui.session?.(`▶ afterAll round ${r}/${rounds}: ${aft.modules.join(', ')} (conc=${conc})`);
        await runModulesListOnAll(contextsAll, aft.modules, conc, dMod);
        if (r<rounds && dRnd>0) { ui.session?.(`[afterAll] jeda ${dRnd}ms`); await sleep(dRnd); }
      }
    }

    if (contextsAll.length && !get(CFG,'ui.disableTicker', false)){ startSessionTicker(contextsAll, ui); }

    // ====== IDLE / KEEP-ALIVE LOOP (baru) ======
    const IDLE_MS_DEFAULT = Number(get(CFG,'flow.idleMs', 300000));
    const KA_idleOnly = Boolean(get(CFG,'keepAlive.idleOnly', false));
    const KA_hours    = Number(get(CFG,'keepAlive.hours', 0));
    const KA_sleepMs  = Number(get(CFG,'keepAlive.sleepMs', IDLE_MS_DEFAULT));
    const KA_endAt    = KA_idleOnly && KA_hours>0 ? (Date.now() + KA_hours*60*60*1000) : 0;
    const REPEAT      = get(CFG,'flow.repeatRounds', true);

    while (REPEAT){
      if (!KA_idleOnly){
        // mode normal: jalankan modul tiap putaran
        await runRound(contextsAll, makeLogger());
      } else {
        // mode idleOnly: tidak jalankan modul, hanya jaga sesi
        if (KA_endAt && Date.now() > KA_endAt){
          ui.session?.(`keepAlive done (≈${KA_hours}h)`);
          break;
        }
      }

      // ping/refresh per akun saat idle
      if (KA_idleOnly || get(CFG,'keepAlive.ping.enabled', false)){
        await Promise.all(contextsAll.map(keepAliveTick));
      }

      const SLEEP = KA_sleepMs>0 ? KA_sleepMs : IDLE_MS_DEFAULT;
      ui.session?.(`[idle] ${SLEEP}ms`);
      await sleep(SLEEP);
    }
  }catch(e){
    console.error('[fatal]', e.response?.status || '', e.response?.data ?? e.stack ?? e.message);
  }
})();
