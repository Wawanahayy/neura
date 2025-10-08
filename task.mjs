#!/usr/bin/env node
// task.mjs — fetch tasks from infra first, fallback to app; always show compact summary; auto-claim

function norm(x){ return String(x ?? '').trim(); }
function row(it){
  const id   = norm(it.id).slice(0,24).padEnd(24);
  const name = norm(it.name||it.title).slice(0,28).padEnd(28);
  const pts  = String(it.points ?? it.pts ?? '').padStart(3);
  const st   = norm(it.status || it.state || (it.claimed ? 'claimed' : (it.claimable ? 'claimable' : ''))).padEnd(12);
  const prog = norm(it.progress || (it.current && it.total ? `${it.current}/${it.total}` : '')).padEnd(7);
  return `${id} ${name} ${pts} ${st} ${prog}`;
}

function extractList(data){
  if (!data) return [];
  if (Array.isArray(data)) return data;
  if (Array.isArray(data.tasks)) return data.tasks;
  if (Array.isArray(data.data))  return data.data;
  return [];
}

async function fetchTasks(http, api){
  // 1) infra
  try {
    const r = await http.get(api.endpoints.infraBase + '/api/tasks');
    if (r.status === 200) return extractList(r.data);
  } catch {}
  // 2) app (fallback)
  try {
    const r = await http.get(api.endpoints.appBase + '/api/tasks');
    if (r.status === 200) return extractList(r.data);
  } catch {}
  return [];
}

function isClaimable(t){
  if (t.claimable === true) return true;
  const s = norm(t.status);
  return /claim/i.test(s) && !/claimed/i.test(s);
}

async function tryClaim(http, api, id, log){
  // coba ke infra lalu app
  const urls = [
    api.endpoints.infraBase + `/api/tasks/${id}/claim`,
    api.endpoints.appBase   + `/api/tasks/${id}/claim`,
  ];
  for (const u of urls){
    try {
      const r = await http.post(u, {});
      if (r.status === 200) { log.mini(`claim ${id} → 200`); return true; }
      log.mini(`claim ${id} → ${r.status}`);
    } catch (e) {
      log.mini(`claim ${id} x ${e.code || e.message}`);
    }
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
    return;
  }

  if (!list.length){ log.mini('🗒️ No tasks.'); return; }

  log.mini('🗒️ Tasks (ID NAME PTS STATUS PROGRESS)');
  for (const it of list) log.mini(row(it));

  const claimable = list.filter(isClaimable);
  if (!claimable.length) { log.mini('No claimable tasks.'); return; }

  for (const t of claimable) {
    await tryClaim(http, api, t.id, log);
  }
}

export default { run };
