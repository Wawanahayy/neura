#!/usr/bin/env node
// game.mjs — collect pulses first, then visit locations one-by-one (3s delay), with ECONNRESET retries

const get   = (o,p,d)=>{ try{ return p.split('.').reduce((x,k)=> (x&&k in x)?x[k]:undefined,o) ?? d; }catch{ return d; } };
const sleep = (ms)=> new Promise(r=>setTimeout(r,ms));

function isRetryable(err){
  const code = String(err?.code || '').toUpperCase();
  if (code === 'ECONNRESET' || code === 'ECONNABORTED' || code === 'ETIMEDOUT') return true;
  const st = err?.response?.status;
  return st === 502 || st === 503 || st === 504;
}

async function withRetry(fn, { attempts=3, baseDelayMs=300, backoff=1.6, jitterMs=100 } = {}, log){
  let last;
  for (let i=0;i<attempts;i++){
    try{ return await fn(); }
    catch(e){
      last = e;
      if (!isRetryable(e) || i === attempts-1) throw e;
      const delay = Math.round(baseDelayMs * Math.pow(backoff, i) + Math.random()*jitterMs);
      if (log?.level !== 'silent') log.warn?.(`retry #${i+1}/${attempts} in ${delay}ms → ${e.code||e.response?.status||e.message}`);
      await sleep(delay);
    }
  }
  throw last;
}

function url(api){
  const base = String(api.endpoints?.infraBase || '').replace(/\/+$/,'');
  const path = String(api.endpoints?.eventsPath || '/api/events');
  return base + path;
}
function postEvent(http, api, body){
  return http.post(url(api), body);
}

export async function run(ctx){
  const { http, api, config, log } = ctx;
  log.mini('\n▶ game.run()');

  // ====== PARAMS ======
  const maxPulse   = Number(get(config,'game.maxPulseSearch',10));
  const attempts   = Number(get(config,'game.perLocationRetry.attempts',3));
  const baseDelay  = Number(get(config,'game.perLocationRetry.baseDelayMs',300));
  const backoff    = Number(get(config,'game.perLocationRetry.backoff',1.6));
  const jitterMs   = Number(get(config,'game.perLocationRetry.jitterMs',100));
  const retryOpts  = { attempts, baseDelayMs: baseDelay, backoff, jitterMs };

  // ====== 1) COLLECT PULSES ======
  for (let i=1; i<=maxPulse; i++){
    const body = { type:'pulse:collectPulse', payload:{ id:`pulse:${i}` } };
    try{
      const r = await withRetry(() => postEvent(http, api, body), retryOpts, log);
      log.mini(`pulse:${i} → ${r.status}`);
    }catch(e){
      log.mini(`pulse:${i} x ${e.code || e.response?.status || e.message}`);
    }
  }

  // ====== 2) VISIT AFTER PULSE ======
  // configurable list; default to 5 lokasi typical di game
  const defaultVisits = [
    { type:'game:visitFountain',        payload:{} },
    { type:'game:visitOracle',          payload:{} },
    { type:'game:visitBridge',          payload:{} },
    { type:'game:visitObservationDeck', payload:{} },
    { type:'game:visitValidatorHouse',  payload:{} },
  ];
  const visits = Array.isArray(get(config,'game.visits',null)) && get(config,'game.visits',null).length
    ? get(config,'game.visits')
    : defaultVisits;

  const visitDelayMs = Number(get(config,'game.visitDelayMs',3000)); // 3s default

  for (const v of visits){
    const body = { type: v.type, payload: v.payload || {} };
    try{
      const r = await withRetry(() => postEvent(http, api, body), retryOpts, log);
      // tampilkan ringkasan yang enak dibaca
      const short = v.type.startsWith('game:visit') ? v.type.replace('game:visit','') : v.type;
      log.mini(`visit ${short} → ${r.status}`);
    }catch(e){
      const short = v.type.startsWith('game:visit') ? v.type.replace('game:visit','') : v.type;
      log.mini(`visit ${short} x ${e.code || e.response?.status || e.message}`);
    }
    if (visitDelayMs > 0) await sleep(visitDelayMs);
  }
}

export default { run };
