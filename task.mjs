#!/usr/bin/env node
// task.mjs — fetch infra→app; compact summary; auto-claim; return status for orchestrator
// v3.2 — progress fix, explicit return status (NO_TASKS/NO_CLAIMABLE/CLAIMED)

function norm(x){ return String(x ?? '').trim(); }
function toInt(x){ const n = Number(x); return Number.isFinite(n) ? n : 0; }
const sleep = (ms)=> new Promise(r=>setTimeout(r, ms));

function progressStr(t){
  // dukung t.progress as object/string atau pair current/total
  const p = t.progress;
  if (p && typeof p === 'object'){
    const cur = toInt(p.current ?? p.done ?? p.value);
    const tot = toInt(p.total ?? p.max);
    if (tot) return `${cur}/${tot}`;
    const pct = p.percent ?? p.percentage;
    if (pct != null) return `${String(pct).replace('%','')}%`;
    try { return JSON.stringify(p); } catch { return ''; }
  }
  if (typeof p === 'string') return norm(p);
  const cur = toInt(t.current);
  const tot = toInt(t.total);
  if (tot) return `${cur}/${tot}`;
  return '';
}

function row(it){
  const id   = norm(it.id || it.taskId).slice(0,24).padEnd(24);
  const name = norm(it.name || it.title).slice(0,28).padEnd(28);
  const pts  = String(it.points ?? it.pts ?? it.reward ?? '').padStart(3);
  const st   = norm(it.status || it.state || (it.claimed ? 'claimed' : (it.claimable ? 'claimable' : ''))).padEnd(12);
  const prog = progressStr(it).slice(0,12).padEnd(12);
  return `${id} ${name} ${pts} ${st} ${prog}`;
}

function extractList(data){
  if (!data) return [];
  if (Array.isArray(data)) return data;
  const paths = [
    ['tasks'], ['data'], ['data','tasks'],
    ['result'], ['result','tasks'],
    ['payload'], ['payload','tasks'],
  ];
  for (const p of paths){
    let cur = data;
    for (const k of p) cur = cur && typeof cur==='object' ? cur[k] : undefined;
    if (Array.isArray(cur)) return cur;
  }
  return [];
}

function dedupeById(list){
  const seen = new Set();
  const out = [];
  for (const it of list){
    const id = norm(it.id || it.taskId || it._id || it.slug || it.name || it.title);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push({ ...it, id });
  }
  return out;
}

async function fetchTasks(http, api){
  try {
    const r = await http.get(api.endpoints.infraBase + '/api/tasks');
    if (r?.status === 200){
      const l = extractList(r.data);
      if (l.length) return dedupeById(l);
    }
  } catch {}
  try {
    const r = await http.get(api.endpoints.appBase + '/api/tasks');
    if (r?.status === 200){
      const l = extractList(r.data);
      if (l.length) return dedupeById(l);
    }
  } catch {}
  return [];
}

function isClaimed(t){
  if (t.claimed === true) return true;
  const s = norm(t.status || t.state);
  return /(claimed|done|completed|received|rewarded)/i.test(s);
}
function isExplicitClaimable(t){
  if (t.claimable === true) return true;
  const s = norm(t.status || t.state);
  return /(claimable|ready|complete|finished|available)/i.test(s) && !/claimed/i.test(s);
}
function progressLooksComplete(t){
  const cur = toInt((t.progress && t.progress.current) ?? t.current);
  const tot = toInt((t.progress && t.progress.total) ?? t.total);
  if (tot > 0 && cur >= tot) return true;
  const p = norm(progressStr(t));
  if (/^100\s*%$/.test(p)) return true;
  const m = p.match(/(\d+)\s*\/\s*(\d+)/);
  return !!(m && Number(m[1]) >= Number(m[2]));
}
function looksDaily(t){
  const n = norm(t.name || t.title);
  const tag = String(t.tag || t.type || '');
  return /(daily|harian)/i.test(n) || /(daily|harian)/i.test(tag);
}
function isProbablyClaimable(t){
  if (isExplicitClaimable(t)) return true;
  if (isClaimed(t)) return false;
  if (progressLooksComplete(t)) return true;
  if (looksDaily(t)) return true;
  return false;
}

function alreadyClaimedErr(e){
  const sc = e?.response?.status;
  const msg = norm(e?.response?.data?.message || e?.response?.data?.error || e?.message || '');
  return sc === 409 || /already\s*(claimed|received)/i.test(msg);
}

async function tryClaimOnce(http, url, id, log){
  try {
    const r = await http.post(url, {});
    if (r?.status === 200 || r?.status === 201){ log.mini(`claim ${id} → ${r.status}`); return 'ok'; }
    log.mini(`claim ${id} → ${r.status}`); return 'soft';
  } catch(e){
    if (alreadyClaimedErr(e)){ log.mini(`claim ${id} → already`); return 'already'; }
    log.mini(`claim ${id} x ${e.code || e.message}`); return 'error';
  }
}

async function tryClaim(http, api, id, log){
  const urls = [
    api.endpoints.infraBase + `/api/tasks/${id}/claim`,
    api.endpoints.appBase   + `/api/tasks/${id}/claim`,
  ];
  for (const u of urls){
    const r = await tryClaimOnce(http, u, id, log);
    if (r === 'ok' || r === 'already') return true;
    await sleep(250);
  }
  return false;
}

export async function run(ctx){
  const { http, api, log } = ctx;

  let list = [];
  try {
    list = await fetchTasks(http, api);
  } catch (e) {
    log.mini(`task error → ${e.code || e.message}`);
    return { status: 'NO_TASKS', total: 0, claimable: 0, claimedIds: [] };
  }

  if (!list.length){
    log.mini('🗒️ No tasks.');
    // kasih sinyal jelas ke orchestrator: lanjut ke gameplay lain
    return { status: 'NO_TASKS', total: 0, claimable: 0, claimedIds: [] };
  }

  log.mini('🗒️ Tasks (ID NAME PTS STATUS PROGRESS)');
  for (const it of list) log.mini(row(it));

  const candidates = list.filter(t => isProbablyClaimable(t) && !isClaimed(t));
  if (!candidates.length){
    log.mini('No claimable tasks.');
    return { status: 'NO_CLAIMABLE', total: list.length, claimable: 0, claimedIds: [] };
  }

  const claimedIds = [];
  for (const t of candidates){
    const ok = await tryClaim(http, api, t.id, log);
    if (ok) claimedIds.push(t.id);
    await sleep(200);
  }

  if (!claimedIds.length){
    // tidak ada yang sukses di-claim, tapi tetap jangan diem
    return { status: 'NO_CLAIMABLE', total: list.length, claimable: candidates.length, claimedIds };
  }

  return { status: 'CLAIMED', total: list.length, claimable: candidates.length, claimedIds };
}

export default { run };
