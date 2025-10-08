// swap.mjs (router call; harga dari subgraph sudah ditangani di tool swapmu yang besar)
import { ethers } from 'ethers';
export async function run(ctx) {
  const { wallet, config, log } = ctx;
  const sw = config.swap || {};
  if (!sw?.tx?.to || !sw?.tx?.abi || !sw?.tx?.method) { log.info('swap: router tx belum dikonfigurasi'); return; }
  const provider = new ethers.JsonRpcProvider(process.env.NEURA_RPC);
  const signer = wallet.connect(provider);
  const iface = new ethers.Interface(sw.tx.abi);
  // susun args sesuai placeholder yang kamu pakai ($TOKEN_IN, $TOKEN_OUT, dst)
  // … panggil sendTransaction …
  log.info('swap: (contoh) siap eksekusi, tinggal isi args sesuai config');
}
