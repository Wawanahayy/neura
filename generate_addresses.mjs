#!/usr/bin/env node


import fs from 'node:fs/promises';
import { Wallet } from 'ethers';

const IN_FILE = 'privatekeys.txt';
const OUT_FILE = 'address.txt';

async function main() {
  try {
    const raw = await fs.readFile(IN_FILE, 'utf8');
    const lines = raw.split(/\r?\n/).map(l => l.trim());
    const out = [];
    let idx = 0;
    for (const line of lines) {
      idx++;
      if (!line) continue; // skip empty
      // Accept either 0x-prefixed or raw hex, optionally an extra comment after a space
      const token = line.split(/\s+/)[0];
      let key = token.startsWith('0x') ? token : `0x${token}`;
      try {
        const w = new Wallet(key);
        out.push(w.address);
      } catch (err) {
        console.error(`Line ${idx}: invalid private key -> skipped (${token})`);
      }
    }

    await fs.writeFile(OUT_FILE, out.join('\n') + (out.length ? '\n' : ''), { encoding: 'utf8', mode: 0o600 });
    console.log(`Done. Wrote ${out.length} addresses to ${OUT_FILE}`);
  } catch (err) {
    if (err.code === 'ENOENT') {
      console.error(`Input file "${IN_FILE}" not found. Create it with one private key per line.`);
    } else {
      console.error('Error:', err);
    }
    process.exit(1);
  }
}

main();
