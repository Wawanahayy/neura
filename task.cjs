// task.mjs
export async function run(ctx) {
  const { http, config, api, log } = ctx;
  const base = api.endpoints.infraBase;
  try {
    // contoh: GET /api/tasks
    const r = await http.get(`${base}${api.endpoints.tasksPath || '/api/tasks'}`);
    if (r.status >= 400) throw new Error(`tasks ${r.status}`);
    const tasks = Array.isArray(r.data?.tasks) ? r.data.tasks : (Array.isArray(r.data) ? r.data : []);
    log.info(`🗒️ tasks: ${tasks.length}`);
    // … lakukan logic klaim/print progress sesuai config.claim …
  } catch (e) {
    log.info(`task error → ${e.response?.status || e.code || e.message}`);
  }
}
