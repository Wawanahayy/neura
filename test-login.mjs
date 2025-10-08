#!/usr/bin/env node
/**
 * test-login.mjs
 * — uji SIWE login otomatis (Trustline integrated)
 * — debug aktif otomatis (tanpa DEBUG=1)
 */

import core from './auth-core.mjs';

const DEBUG = true; // <-- auto-debug ON
const { APP_INFRA = 'https://neuraverse-testnet.infra.neuraprotocol.io' } = process.env;

async function main() {
  const keys = core.getPrivateKeys();
  const proxies = core.getProxies();

  console.log(`🔑 total akun: ${keys.length}`);
  if (proxies.length) console.log(`🌐 total proxy: ${proxies.length}`);

  await core.forEachAccount({
    keys,
    proxies,
    cb: async ({ address, http, index, bearer, proxy }) => {
      console.log(`\n== Account #${index} (${address}) | proxy=${proxy || 'none'} ==`);
      if (DEBUG) console.log('[dbg] bearer:', bearer?.slice(0, 10) + '…');

      try {
        // ---- /api/account
        const acc = await http.get(`${APP_INFRA}/api/account`);
        if (acc.status >= 400) throw new Error(`/api/account ${acc.status}`);
        const info = acc.data || {};
        console.log('👤 account:', {
          points: info.neuraPoints,
          volume: info.tradingVolume,
          address: info.address?.slice(0, 10) + '...',
        });
        if (DEBUG) console.log('[dbg] raw account:', info);
      } catch (err) {
        console.log('⚠️ account error:', err.message);
      }

      try {
        // ---- /api/pulses
        const pulses = await http.get(`${APP_INFRA}/api/pulses/`);
        const data = pulses.data;
        const count = Array.isArray(data) ? data.length : (data?.length ?? 'n/a');
        console.log(`📡 pulses: ${count}`);
        if (DEBUG && Array.isArray(data) && data.length)
          console.log('[dbg] sample pulse:', data[0]);
      } catch (err) {
        console.log('⚠️ pulses error:', err.message);
      }

      await new Promise(r => setTimeout(r, 500));
    },
  });
}

main().catch(e => {
  console.error('[fatal]', e.message || e);
  process.exit(1);
});
