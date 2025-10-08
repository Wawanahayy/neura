#!/usr/bin/env node
import 'dotenv/config';
import express from 'express';
import { chromium } from 'playwright';

const argv = process.argv.slice(2);
const arg = (k, d=null) => {
  const i = argv.indexOf(`--${k}`); if (i<0) return d;
  const v = argv[i+1]; return v && !v.startsWith('--') ? v : true;
};
const trimq = s => (s==null? s : String(s).trim().replace(/^["']|["']$/g,''));

const TEST_KEY = '1x00000000000000000000AA';
const SITEKEY = trimq(arg('sitekey', process.env.TURNSTILE_SITE_KEY || TEST_KEY));
const PORT = Number(arg('port', process.env.PORT || 3456));
const ORIGIN = `http://127.0.0.1:${PORT}`;
const TIMEOUT = Number(arg('timeout', process.env.TIMEOUT_MS || 30000));
const HEADLESS = (arg('headless', process.env.HEADLESS ?? '1')) !== '0';
const DEBUG = (arg('debug', process.env.DEBUG ?? '1')) !== '0';

const html = (sk, ms) => `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Turnstile local</title>
<script>
  window.__TOKEN__=""; window.__DONE__=false;
  window.tsSolved=function(t){window.__TOKEN__=t||"";window.__DONE__=true;
    var pre=document.getElementById('out')||document.createElement('pre');
    pre.id='out'; pre.textContent=window.__TOKEN__||'NO_TOKEN'; document.body.appendChild(pre);}
</script>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>body{font-family:system-ui,Segoe UI,Roboto,Arial;margin:16px}</style></head>
<body>
  <form id="f">
    <div class="cf-turnstile" data-sitekey="${sk}" data-callback="tsSolved"></div>
    <button type="button" id="btn">Get token</button>
  </form>
  <script>
    async function waitTok(ms){
      const end=Date.now()+ms;
      while(Date.now()<end){
        if(window.__DONE__&&window.__TOKEN__) return window.__TOKEN__;
        const inp=document.querySelector('input[name="cf-turnstile-response"]');
        if(inp&&inp.value){ tsSolved(inp.value); return inp.value; }
        try{ if(window.turnstile&&typeof window.turnstile.getResponse==='function'){
          const r=window.turnstile.getResponse(); if(r){ tsSolved(r); return r; } } }catch(_){}
        await new Promise(r=>setTimeout(r,150));
      } return null;
    }
    async function expose(){
      if(!window.__DONE__){
        const tok=await waitTok(${ms});
        if(tok&&!window.__DONE__) tsSolved(tok);
        if(!tok&&!window.__DONE__){
          const pre=document.getElementById('out')||document.createElement('pre');
          pre.id='out'; pre.textContent='NO_TOKEN'; document.body.appendChild(pre);
        }
      }
    }
    document.getElementById('btn').addEventListener('click',expose);
    setTimeout(()=>document.getElementById('btn').click(),900);
  </script>
</body></html>`;

const app = express();
app.get('/', (_req,res)=>res.type('html').send(html(SITEKEY, TIMEOUT)));

const server = app.listen(PORT, async () => {
  const browser = await chromium.launch({ headless: HEADLESS, args:['--disable-blink-features=AutomationControlled'] });
  const ctx = await browser.newContext({
    viewport:{width:1024,height:720},
    userAgent:'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36'
  });
  const page = await ctx.newPage();
  if (DEBUG) {
    page.on('console', m => { try{ console.error('[console]', m.type(), m.text()); }catch{} });
    page.on('pageerror', e => console.error('[pageerror]', e?.message || e));
    page.on('requestfailed', r => console.error('[requestfailed]', r.url(), r.failure()?.errorText));
  }

  try {
    await page.goto(ORIGIN, { waitUntil:'domcontentloaded' });
    await page.click('#btn').catch(()=>{});
    await page.waitForSelector('pre#out', { timeout: TIMEOUT });
    const token = (await page.textContent('pre#out'))?.trim() || '';
    if (!token || token==='NO_TOKEN') {
      console.error('ERROR: token not found (cek Allowed domains di widget & koneksi ke challenges.cloudflare.com)');
      await browser.close().catch(()=>{}); server.close(()=>process.exit(3)); return;
    }
    process.stdout.write(token + '\n');
    await browser.close().catch(()=>{}); server.close(()=>process.exit(0));
  } catch (e) {
    console.error('ERROR:', e?.message || e);
    try { await browser.close(); } catch {}
    server.close(()=>process.exit(4));
  }
});
