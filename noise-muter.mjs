// noise-muter.mjs — potong log liar (JSON-RPC, coalesce, dll) agar tak pecah panel
export function installNoiseMuter(ui, opts={}){
  const passEsc = s => /\x1b\[/.test(s); // biarkan ESC (gambar TUI) lewat
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);

  const patRpc = /JsonRpcProvider .*?retry in \d+s|the URL is wrong or the node is not started/i;
  const patCoalesce = /could not coalesce/i;
  const patAxios = /ECONNRESET|ETIMEDOUT|ENETUNREACH|EAI_AGAIN/i;

  const throttle = {};
  const shouldEmit = (key, ms=3000)=>{
    const now = Date.now();
    if (!throttle[key] || now - throttle[key] > ms){ throttle[key]=now; return true; }
    return false;
  };

  const makeSink = (orig) => {
    let buf = '';
    return function(chunk, enc, cb){
      const s = typeof chunk === 'string' ? chunk : (chunk ? chunk.toString(enc || 'utf8') : '');
      if (!s) { if (cb) cb(); return true; }
      if (passEsc(s)) return orig(chunk, enc, cb); // biarkan TUI
      buf += s;
      const parts = buf.split(/\n/);
      buf = parts.pop();
      for (let lineRaw of parts){
        let line = String(lineRaw || '').replace(/\r/g,'');
        if (!line.trim()) continue;
        // normalisasi & pendekkan
        const stripped = line.replace(/\x1b\[[0-9;]*m/g,'').replace(/[\u0000-\u001F\u007F]/g,'').trim();

        if (patRpc.test(stripped)) {
          if (shouldEmit('rpc', 5000)) ui?.session?.('⚠️ RPC not ready; retry');
          continue;
        }
        if (patCoalesce.test(stripped)) {
          if (shouldEmit('coalesce', 4000)) ui?.session?.('⚠️ swap router: coalesce error');
          continue;
        }
        if (patAxios.test(stripped)) {
          if (shouldEmit('net', 4000)) ui?.session?.('⚠️ network hiccup');
          continue;
        }
        // fallback: alihkan ke session agar tidak nembus panel
        if (ui?.session) { ui.session(stripped); continue; }
        // jika UI mati, baru tulis ke terminal biasa
        orig(stripped+'\n');
      }
      if (cb) cb();
      return true;
    };
  };

  process.stdout.write = makeSink(origOut);
  process.stderr.write = makeSink(origErr);
}
