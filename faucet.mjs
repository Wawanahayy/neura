// faucet.mjs
import { ethers } from 'ethers';

function toLowerObjKeys(o){ const r={}; for(const k of Object.keys(o||{})) r[k.toLowerCase()]=o[k]; return r; }

export async function run(ctx){
  const { http, api, config, log, address } = ctx;
  log.mini('🪙 faucet.run() start');

  // optional: cek poin dari /account
  let pts = null;
  try {
    const r = await http.get(api.endpoints.infraBase + api.endpoints.accountPath);
    const acc = toLowerObjKeys(r.data||{});
    pts = Number(acc.points ?? acc.neurapoints ?? acc.neuraPoints ?? NaN);
  } catch {}
  const min = Number(config.claim?.minPoints ?? 0);
  if (config.claim?.skipIfBelowPoints && Number.isFinite(pts)) {
    log.mini(`neuraPoints = ${pts}; min = ${min}`);
    if (pts < min){ log.mini(' ⏭️    skip faucet (points < minPoints)'); return; }
  }

  const candidates = (api.endpoints.claimPaths||[]).map(p=>[
    api.endpoints.infraBase + p,
    api.endpoints.appBase   + p,
  ]).flat();

  const bodies = (api.claimBodies || []).map(b=>JSON.parse(JSON.stringify(b).replace(/\$ADDRESS/g, address)));

  for (const url of candidates){
    for (const body of bodies){
      try {
        const r = await http.post(url, body);
        if (r.status === 200) {
          const msg = (r.data && (r.data.message || r.data.status || 'ok'));
          log.mini(`🎉 faucet OK${msg?` — ${msg}`:''}`);
          return;
        }
        // tampilkan reason singkat
        let reason = '';
        try { reason = r.data?.message || r.data?.error || ''; } catch {}
        log.mini(`→ POST ${new URL(url).pathname} ${r.status}${reason?` "${reason}"`:''}`);
      } catch (e) {
        log.mini(`→ POST ${new URL(url).pathname} x ${e.code || e.message}`);
      }
    }
  }
  log.mini('faucet: tidak ada endpoint yang berhasil');
}
export default { run };
