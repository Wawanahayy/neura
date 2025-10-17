#!/usr/bin/env node
// index.js solve turnstile via captcha service 
// turnstile.js

const axios = require('axios');
require('dotenv').config();

const API_KEY = process.env.API_KEY;
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || '0x4AAAAAAAM8ceq5KhP1uJBt';
const TURNSTILE_PAGE_URL = process.env.TURNSTILE_PAGE_URL || 'https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/pat/98ae80b519fbe2f8/1759851689768/2887c9670285dc18e86bb3b0bf41bb405c6f2389812e14824e6c2575e770fd1c/MTqrdlmcNCHcTru=';

const POLL_MS = Number(process.env.POLL_MS || 5000);
const MAX_WAIT_SEC = Number(process.env.MAX_WAIT_SEC || 180);

if (!API_KEY || !TURNSTILE_SITE_KEY || !TURNSTILE_PAGE_URL) {
  console.error('Missing ENV. Need: API_KEY, TURNSTILE_SITE_KEY, TURNSTILE_PAGE_URL');
  process.exit(2);
}

const api = axios.create({
  baseURL: 'https://2captcha.com',
  timeout: 60000,
});

async function solveCaptcha() {
  const res = await api.post('/in.php', null, {
    params: {
      key: API_KEY,
      method: 'turnstile',
      sitekey: TURNSTILE_SITE_KEY,
      pageurl: TURNSTILE_PAGE_URL,
      json: 0,
    },
  });

  const body = String(res.data);

  if (body.startsWith('OK|')) {
    const id = body.split('|')[1];
    return id;
  }

  const known = [
    'ERROR_WRONG_USER_KEY',
    'ERROR_ZERO_BALANCE',
    'ERROR_WRONG_SITEKEY',
    'ERROR_WRONG_CAPTCHA_ID',
    'ERROR_IP_NOT_ALLOWED',
    'ERROR_PAGEURL',
  ];
  for (const k of known) {
    if (body.includes(k)) {
      throw new Error(`2Captcha submit error: ${k}`);
    }
  }

  throw new Error(`2Captcha submit error: ${body}`);
}


async function getSolution(captchaId) {
  const start = Date.now();

  await sleep(POLL_MS);

  while (true) {
    if ((Date.now() - start) / 1000 > MAX_WAIT_SEC) {
      throw new Error(`Timeout waiting for solution (> ${MAX_WAIT_SEC}s)`);
    }

    const res = await api.get('/res.php', {
      params: {
        key: API_KEY,
        action: 'get',
        id: captchaId,
        json: 0,
      },
    });

    const body = String(res.data);

    if (body.startsWith('OK|')) {
      return body.split('|')[1];
    }

    if (body === 'CAPCHA_NOT_READY') {
      await sleep(POLL_MS);
      continue;
    }

    // error lain
    throw new Error(`2Captcha result error: ${body}`);
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

(async () => {
  try {
    const id = await solveCaptcha();
    console.error(`[2captcha] submitted, id=${id}`);
    const token = await getSolution(id);
    process.stdout.write(token + '\n');
    process.exit(0);
  } catch (err) {
    console.error('[2captcha] failed:', err && err.message ? err.message : err);
    process.exit(1);
  }
})();

module.exports = { solveCaptcha, getSolution };
