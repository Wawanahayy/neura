#!/usr/bin/env node
// faucet.mjs 

import { ethers } from 'ethers';

const sleep = (ms)=> new Promise(r=>setTimeout(r,ms));

function join(base, p){
  const b = String(base||'').replace(/\/+$/,'');
  const s = String(p||'').replace(/^\/+/,'');
  return b + '/' + s;
}
function uniq(arr){ const s=new Set(); const out=[]; for(const x of arr){ if(!x) continue; const k=String(x); if(s.has(k)) continue; s.add(k); out.push(x);} return out; }

function buildCandidateUrls(api){
  const app   = api?.endpoints?.appBase;
  const infra = api?.endpoints?.infraBase;
  const urls  = [];
  if (app)   urls.push(join(app,   '/api/faucet')); // match successful curl
  if (infra) urls.push(join(infra, '/api/faucet')); // fallback only
  return uniq(urls);
}

export async function run(ctx){
  const { http, api, config, log, address } = ctx;
  log.mini('🪙 faucet.run() start');

  try {
    const accUrl = join(api?.endpoints?.infraBase, api?.endpoints?.accountPath || '/api/account');
    const r = await http.get(accUrl);
    const d = r?.data || {};
    const pts = Number(d.neuraPoints ?? d.neurapoints ?? d.points ?? NaN);
    const min = Number(config?.claim?.minPoints ?? 0);
    if (config?.claim?.skipIfBelowPoints && Number.isFinite(pts)) {
      log.mini(`neuraPoints = ${pts}; min = ${min}`);
      if (pts < min){ log.mini(' ⏭️  skip faucet (points < minPoints)'); return; }
    }
  } catch {/* ignore */}

  const urls = buildCandidateUrls(api);
  const csAddr = ethers.getAddress(address);

  const maxAttemptsPerUrl = Math.max(1, Number(config?.claim?.maxAttempts ?? 3));
  const backoffBaseMs     = Math.max(0, Number(config?.claim?.retryBaseMs ?? 600)); // small backoff to calm CF
  const jitterMs          = Math.max(0, Number(config?.claim?.retryJitterMs ?? 200));

  const body = { address: csAddr, userLoggedIn: true, chainId: 11155111 }; // EXACT like curl

  for (const url of urls){
    const path = new URL(url).pathname;

    let ok = false;
    for (let attempt=1; attempt<=maxAttemptsPerUrl; attempt++){
      try{
        const r = await http.post(url, body, { headers: { 'content-type':'application/json' } });
        const msg = (r?.data?.message || r?.data?.status || '').toString();
        if (r.status === 200) {
          log.mini(`🎉 faucet OK via ${path} (try ${attempt}/${maxAttemptsPerUrl}) — ${msg || 'ok'}`);
          ok = true;
          break;
        }

        if (r.status === 404) { 
          log.mini(`→ POST ${path} 404 (skip URL)`);
          break;
        }

        const reason = msg || (r?.data?.error || '').toString();
        log.mini(`→ POST ${path} ${r.status}${reason?` "${reason}"`:''} (try ${attempt}/${maxAttemptsPerUrl})`);

        if (r.status === 403 && /suspicious|forbidden|blocked/i.test(reason || '')) {
          log.mini(` ⛔️ stop retries for ${path} due to 403 anti-abuse`);
          break;
        }

      } catch(e){
        log.mini(`→ POST ${path} x ${e?.code || e?.message} (try ${attempt}/${maxAttemptsPerUrl})`);
      }

      if (attempt < maxAttemptsPerUrl){
        const wait = Math.floor(backoffBaseMs * Math.pow(1.5, attempt-1) + Math.random()*jitterMs);
        if (wait > 0) await sleep(wait);
      }
    }

    if (ok) return; 
  }

  log.mini('faucet: tidak ada endpoint yang berhasil (stopped after limited attempts)');
}

export default { run };
