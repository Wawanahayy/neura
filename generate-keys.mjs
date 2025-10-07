#!/usr/bin/env node
/**
 * generate-keys.mjs
 * Output:
 *   - mnemonic.txt (24 kata, 1 baris each run, tanpa header/warning)
 *   - privatekeys.txt (1 baris = 1 private key, tanpa header/warning)
 *
 * Pakai:
 *   node generate-keys.mjs            # default 5 akun
 *   node generate-keys.mjs --count=20 # 20 akun
 *
 * Note:
 *   - Jika file sudah ada, hasil akan DITAMBAHKAN (append) di baris baru.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// arg parsing sederhana
const argv = new Map(process.argv.slice(2).map(s => {
  const m = s.match(/^--([^=]+)(=(.*))?$/);
  return m ? [m[1], m[3] ?? "1"] : [s, "1"];
}));

const COUNT = Math.max(1, Number(argv.get("count") ?? 50));
const OUT_MNEMONIC = path.resolve(__dirname, "mnemonic.txt");
const OUT_PRIVATE  = path.resolve(__dirname, "privatekeys.txt");

// derivation path prefix (BIP44 ETH)
const DERIVATION_PREFIX = `m/44'/60'/0'/0/`;

(async () => {
  try {
    // 24-kata: pakai 32 byte entropy
    const entropy = ethers.randomBytes(32);
    const mnemonic = ethers.Mnemonic.fromEntropy(entropy);
    const phrase = mnemonic.phrase; // 24 words

    // derive N akun
    const lines = [];
    for (let i = 0; i < COUNT; i++) {
      const pathI = `${DERIVATION_PREFIX}${i}`;
      const w = ethers.HDNodeWallet.fromPhrase(phrase, undefined, pathI);
      lines.push(w.privateKey); // 1 baris = 1 PK
    }

    // tulis file dengan append (jika file belum ada, akan dibuat)
    // mnemonic: satu baris per run
    fs.writeFileSync(OUT_MNEMONIC, phrase + "\n", { encoding: "utf8", flag: "a" });

    // privatekeys: setiap private key 1 baris, tambahkan newline terakhir
    fs.writeFileSync(OUT_PRIVATE, lines.join("\n") + "\n", { encoding: "utf8", flag: "a" });

    console.log("✅ Done:");
    console.log("  mnemonic.txt   (24 kata, appended if exists)");
    console.log("  privatekeys.txt (", COUNT, "akun, appended if exists )");
  } catch (e) {
    console.error("Error:", e.message);
    process.exit(1);
  }
})();
