// faucet.mjs — robust faucet caller (prefer appBase → fallback), payload & 404-aware
import { ethers } from 'ethers';

function toLowerObjKeys(o){ const r={}; for(const k of Object.keys(o||{})) r[k.toLowerCase()]=o[k]; return r; }
const uniq = (arr)=> Array.from(new Set(arr.filter(Boolean)));
const is2xx = (s)=> s>=200 && s<300;

export async function run(ctx){
  const { http, api, config, log, address } = ctx;
  log.mini('🪙 faucet.run() start');

  const endpoints = api?.endpoints || {};
  const infraBase = String(endpoints.infraBase || '').replace(/\/+$/,'');
  const appBase   = String(endpoints.appBase   || '').replace(/\/+$/,'');
  const accountPath = endpoints.accountPath || '/api/account';
  const claimPaths  = Array.isArray(endpoints.claimPaths) && endpoints.claimPaths.length
    ? endpoints.claimPaths
    : ['/api/faucet'];

  // ---------- (opsional) cek poin dari /account di infra ----------
  let pts = null;
  try {
    if (infraBase) {
      const r = await http.get(infraBase + accountPath);
      const acc = toLowerObjKeys(r.data||{});
      pts = Number(acc.points ?? acc.neurapoints ?? acc.neurapoints ?? acc.neurapoints ?? NaN);
    }
  } catch {}
  const min = Number(config?.claim?.minPoints ?? 0);
  if (config?.claim?.skipIfBelowPoints && Number.isFinite(pts)) {
    log.mini(`neuraPoints = ${pts}; min = ${min}`);
    if (pts < min){ log.mini(' ⏭️    skip faucet (points < minPoints)'); return; }
  }

  // ---------- susun kandidat URL (prioritas appBase lebih dulu untuk faucet) ----------
  // urutan: appBase+p → infraBase+p, per path
  const urlCandidates = claimPaths.flatMap(p => uniq([
    appBase   && (appBase + p),
    infraBase && (infraBase + p),
  ])).filter(Boolean);

  // ---------- susun variasi body ----------
  // pake setting dari api.claimBodies kalau ada; kalau tidak, fallback aman
  const configuredBodies = Array.isArray(api?.claimBodies) ? api.claimBodies : [];
  const fallbackBodies = [
    { address },
    { recipient: address },
    { to: address },
    {}, // beberapa endpoint cukup rely on session
  ];
  const bodies = (configuredBodies.length ? configuredBodies : fallbackBodies)
    .map(b => JSON.parse(JSON.stringify(b).replace(/\$ADDRESS/g, address)));

  // ---------- helper deteksi sukses ----------
  const looksSuccess = (data) => {
    try {
      if (!data) return false;
      const s = typeof data === 'string' ? data : JSON.stringify(data);
      if (data.status === 'success') return true;
      return /distribution successful|airdrop tokens/i.test(s);
    } catch { return false; }
  };
  const shortReason = (d) => {
    try {
      return (d?.message || d?.error || (typeof d === 'string' ? d : ''))?.toString().slice(0,200);
    } catch { return ''; }
  };

  // ---------- eksekusi ----------
  for (const url of urlCandidates){
    const pathname = (()=>{ try { return new URL(url).pathname; } catch { return url; }})();
    for (const body of bodies){
      try {
        const r = await http.post(url, body);
        if (is2xx(r.status)) {
          if (looksSuccess(r.data)) {
            const msg = (r.data && (r.data.message || r.data.status || 'ok'));
            log.mini(`🎉 faucet OK${msg?` — ${msg}`:''}`);
            return;
          }
          // 2xx tapi belum yakin sukses → lanjut coba payload lain
          log.mini(`→ POST ${pathname} ${r.status} (unexpected success payload)`);
          continue;
        }

        // 404 sering terjadi di INFRA untuk /api/faucet → jangan buang waktu dengan payload lain pada URL ini
        if (r.status === 404) {
          log.mini(`→ POST ${pathname} 404 — skip URL ini, coba endpoint lain`);
          break; // pindah ke URL berikutnya
        }

        // tampilkan reason singkat lalu coba payload berikutnya
        const reason = shortReason(r.data);
        log.mini(`→ POST ${pathname} ${r.status}${reason?` "${reason}"`:''}`);
      } catch (e) {
        const code = e?.code || e?.name || '';
        const msg  = (e?.response?.data && shortReason(e.response.data)) || e?.message || '';
        log.mini(`→ POST ${pathname} x ${code}${msg?` "${msg}"`:''}`);
        // network/TLS error → lanjut coba payload lain atau URL lain
        continue;
      }
    }
  }

  log.mini('faucet: tidak ada endpoint yang berhasil');
}

export default { run };
