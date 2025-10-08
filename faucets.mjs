#!/usr/bin/env node
// faucet.mjs — claim faucet w/ neuraPoints pre-check + polite retries + concise logs

import { ethers } from 'ethers';

const sleep = (ms)=> new Promise(r=>setTimeout(r,ms));

function lc(s){ return String(s||'').toLowerCase(); }

function pickNeuraPoints(data){
  // toleran: beberapa backend bentuknya beda-beda
  if (data == null) return null;
  if (typeof data === 'number') return data;
  if (typeof data === 'string' && /^\d+$/.test(data)) return Number(data);

  // bentuk umum:
  // { neuraPoints: 42 }
  // { data: { neuraPoints: 42 } }
  // { account: { neuraPoints: 42 } }
  // { user: { points: 42 } }  // fallback
  const cands = [
    data?.neuraPoints,
    data?.data?.neuraPoints,
    data?.account?.neuraPoints,
    data?.user?.neuraPoints,
    data?.user?.points,
    data?.points,
  ].filter(v=> v!=null);
  return cands.length ? Number(cands[0]) : null;
}

function redactMid(t, keep=6){
  const s=String(t||'');
  return s.length<=keep*2?s:`${s.slice(0,keep)}…${s.slice(-keep)}`;
}

export async function run(ctx){
  const { http, api, config, address, log } = ctx;
  const ep   = api?.endpoints || {};
  const claimCfg = config?.claim || {};
  const stopOn = (claimCfg.stopOn||[]).map(lc);
  const minPoints = Number(claimCfg.minPoints ?? 0);
  const skipLow   = Boolean(claimCfg.skipIfBelowPoints ?? false);

  const bases = [ep.infraBase, ep.appBase].filter(Boolean);
  const paths = Array.isArray(ep.claimPaths) ? ep.claimPaths : ['/api/faucet'];
  const bodies= Array.isArray(api?.claimBodies) && api.claimBodies.length
    ? api.claimBodies
    : [{ address: '$ADDRESS' }, { recipient: '$ADDRESS' }, { to: '$ADDRESS' }, {}];

  log.mini('🪙 faucet.run() start');

  // ===== 1) PRE-CHECK: neuraPoints =====
  let points = null;
  for (const base of bases){
    try {
      const url = `${base}${ep.accountPath || '/api/account'}`;
      const r = await http.get(url);
      // tetap tampilkan garis besar meski silent
      log.api?.(`⇢ GET ${url}`);
      log.api?.(`⇠ GET ${url} ${r.status}`);
      const p = pickNeuraPoints(r.data);
      if (p!=null){ points = p; break; }
    } catch (e) {
      // lanjut ke base berikutnya
    }
  }
  if (points!=null) {
    log.mini(`neuraPoints = ${points}; min = ${minPoints}`);
    if (skipLow && points < minPoints){
      log.mini('⏭️ skip faucet (points < minPoints)');
      return;
    }
  }

  // ===== 2) RETRY SETTINGS =====
  const attempts = Number(claimCfg.attempts ?? claimCfg.maxAttempts ?? 6);
  const factor   = Number(claimCfg.factor ?? 1.6);
  const jitterMs = Number(claimCfg.jitterMs ?? 600);
  const baseDelay= Number(claimCfg.baseDelayMs ?? 1000);
  const maxDelay = Number(claimCfg.maxDelayMs ?? 8000);
  const retryForever = Boolean(claimCfg.retryForever ?? false);

  // helper delay w/ backoff
  const delayFor = (tryIdx)=>{
    const mult = Math.min(maxDelay, Math.floor(baseDelay * Math.pow(factor, Math.max(0,tryIdx-1))));
    const jitter = Math.floor((Math.random()*2-1) * jitterMs);
    return Math.max(0, mult + jitter);
  };

  // ===== 3) claim loop =====
  let success = false;
  let tryCount = 0;

  outer:
  for (let a=1; retryForever || a<=attempts; a++){
    tryCount = a;

    for (const base of bases){
      for (const path of paths){
        // semua body: substitusi $ADDRESS
        for (const b of bodies){
          const payload = {};
          for (const [k,v] of Object.entries(b)) payload[k] = (v==='$ADDRESS') ? address : v;

          const url = `${base}${path}`;
          try{
            log.api?.(`⇢ POST ${url} → ${JSON.stringify(payload)}`);
            const r = await http.post(url, payload);
            const status = r.status;
            // ringkas: tampilkan status + message (kalau ada)
            let msg = '';
            if (r.data && typeof r.data === 'object'){
              msg = r.data.message || r.data.error || '';
            } else if (typeof r.data === 'string') {
              msg = r.data;
            }
            const preview = msg ? ` "${msg}"` : '';
            log.mini(`→ POST ${path} ${status}${preview}`);

            const bodyLc = lc(JSON.stringify(r.data||''));
            if (status >= 200 && status < 300){
              success = true;
              break outer;
            }
            // stopOn check (termasuk insufficient neuraPoints)
            if (stopOn.some(s => bodyLc.includes(s))){
              // berhenti sopan (jangan hajar endpoint lain)
              break outer;
            }
            // 400/403/404 → lanjut coba kombinasi lain
          }catch(e){
            const code = e?.code || e?.message || 'ERR';
            log.mini(`→ POST ${path} x ${code}`);
            // ECONNRESET → tetap lanjut; biar diulang di iterasi berikut
          }
        }
      }
    }

    if (success) break;
    // tidak sukses, tidur dulu sebelum iterasi berikutnya
    const ms = delayFor(a);
    await sleep(ms);
  }

  if (success) {
    log.mini('🎉 faucet OK');
  } else {
    log.mini('faucet: tidak ada endpoint yang berhasil / diberi izin');
  }
}

export default { run };
