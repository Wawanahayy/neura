#!/usr/bin/env node
import axios from 'axios';

const ORIGIN = process.env.NEURAVERSE_ORIGIN || 'https://neuraverse.neuraprotocol.io';

// helper regex
const reAppId = /\b(appId|clientId)\b["']?\s*[:=]\s*["']([a-z0-9]{24,})["']/ig; // ex: cmbpempz2011ll10l7iucga14
const reCaId  = /\b(caId|attestationId|privy-ca-id)\b["']?\s*[:=]\s*["']([0-9a-f-]{36})["']/ig;
const rePrivy = /\bprivy[-_.]?(app|client|ca|env|config)\b/i;

function uniq(arr){ return [...new Set(arr)].filter(Boolean); }

async function get(url){
  const r = await axios.get(url, { timeout: 20000, validateStatus: ()=>true });
  if (r.status >= 400) throw new Error(`GET ${url} → ${r.status}`);
  return r.data;
}

function abs(base, src){
  try { return new URL(src, base).href; } catch { return null; }
}

function* findAll(re, s){
  let m; while ((m = re.exec(s))) yield m;
}

(async () => {
  try {
    console.log('→ fetch', ORIGIN);
    const html = await get(ORIGIN);

    // cari semua <script src=...>
    const scriptSrcs = [];
    for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/ig)) {
      const u = abs(ORIGIN, m[1]); if (u) scriptSrcs.push(u);
    }

    // ikutkan inline code block juga
    const blobs = [ { name: '[inline html]', text: String(html) } ];

    // fetch semua bundle
    for (const src of scriptSrcs.slice(0, 20)) { // batasi 20 file
      try {
        const text = await get(src);
        blobs.push({ name: src, text: String(text) });
      } catch (e) {
        console.warn('warn: gagal fetch', src, String(e.message||e).slice(0,120));
      }
    }

    // scan semua blob
    let appIds = [], caIds = [], hits = [];
    for (const b of blobs) {
      const t = b.text;
      if (!rePrivy.test(t) && !/privy/i.test(t)) continue;

      const apps = [...findAll(reAppId, t)].map(m => m[2]);
      const cas  = [...findAll(reCaId,  t)].map(m => m[2]);

      if (apps.length || cas.length) {
        hits.push({ file: b.name, apps, cas });
        appIds.push(...apps);
        caIds.push(...cas);
      }
    }

    appIds = uniq(appIds);
    caIds  = uniq(caIds);

    console.log('\n=== POSSIBLE PRIVY CONFIG FOUND ===');
    console.log('files w/ privy matches:', hits.map(h => h.file));
    console.log('appIds:', appIds);
    console.log('caIds :', caIds);

    if (!appIds.length && !caIds.length) {
      console.log('\nNo obvious privy ids in bundles. Coba buka site di Chrome → DevTools → Network → filter "siwe/init" dan copy Request Headers persis.');
      process.exit(2);
    }

    // siapin .env patch yang bisa langsung kamu paste
    console.log('\n--- .env candidates (paste yg cocok) ---');
    if (appIds[0]) console.log('PRIVY_APP_ID=', appIds[0]);
    if (caIds[0])  console.log('PRIVY_CA_ID=', caIds[0]);

    process.exit(0);
  } catch (e) {
    console.error('FATAL:', e.message || e);
    process.exit(1);
  }
})();
