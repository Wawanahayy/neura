#!/usr/bin/env node

import { ethers } from 'ethers';

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function checksumFlexible(addr) {
  const s = String(addr || '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(s)) throw new Error(`invalid address format: ${addr}`);
  try { return ethers.getAddress(s); } catch { return ethers.getAddress(s.toLowerCase()); }
}

function materializeArgs(args, vars) {
  if (!Array.isArray(args)) return args;
  return args.map(v => {
    if (typeof v !== 'string') return v;
    return ({
      '$TOKEN': vars.TOKEN,
      '$AMOUNT': vars.AMOUNT,
      '$OWNER': vars.OWNER,
      '$RECIPIENT': vars.RECIPIENT
    }[v]) ?? v;
  });
}

const ERC20_ABI = [
  'function balanceOf(address) view returns (uint256)',
  'function allowance(address,address) view returns (uint256)',
  'function approve(address,uint256) returns (bool)',
  'function transfer(address,uint256) returns (bool)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)'
];

async function ensureAllowance({ signer, tokenAddr, owner, spender, wantAmount, wait, confs, gasLimit, log }) {
  const erc20 = new ethers.Contract(tokenAddr, ERC20_ABI, signer);
  const [allow, sym, dec] = await Promise.all([
    erc20.allowance(owner, spender),
    erc20.symbol().catch(()=> 'TOKEN'),
    erc20.decimals().catch(()=> 18),
  ]);
  if (allow >= wantAmount) {
    log.info(`🔗 allowance OK: ${ethers.formatUnits(allow, dec)} ${sym} ≥ ${ethers.formatUnits(wantAmount, dec)} ${sym}`);
    return;
  }
  log.info(`🔗 approving ${ethers.formatUnits(wantAmount, dec)} ${sym} for ${spender}`);
  const tx = await erc20.approve(spender, wantAmount, ...(gasLimit ? [{ gasLimit: BigInt(gasLimit) }] : []));
  log.info(`📝 approve tx: ${tx.hash}`);
  if (wait) {
    const r = await tx.wait(Math.max(0, Number(confs)));
    log.info(`✅ approve confirmed (block ${r.blockNumber})`);
  }
}

function buildCandidates({ amount, recipient }) {
  return [
    { sig: 'function deposit(uint256 _amount, address _recipient)', args: [ amount, recipient ] },
    { sig: 'function deposit(address _recipient, uint256 _amount)', args: [ recipient, amount ] },
    { sig: 'function deposit(uint256 _amount)',                   args: [ amount ] },
    { sig: 'function bridge(uint256 _amount, address _recipient)',args: [ amount, recipient ] },
    { sig: 'function lock(uint256 _amount, address _recipient)',  args: [ amount, recipient ] },
  ];
}

async function tryCallOne({ signer, to, cand, value, gasLimit, log }) {
  const iface = new ethers.Interface([ cand.sig ]);
  const data  = iface.encodeFunctionData(iface.fragments[0].name, cand.args);

  try {
    await signer.estimateGas({ to, data, value: value ?? 0n });
  } catch (e) {
    throw e; // biar caller bisa coba kandidat berikutnya
  }

  // 2) kirim tx
  const tx = await signer.sendTransaction({ to, data, value: value ?? 0n, ...(gasLimit ? { gasLimit: BigInt(gasLimit) } : {}) });
  log.info(`📝 tx: ${tx.hash}`);
  return tx;
}

export async function run(ctx) {
  const { wallet, config, log } = ctx;
  const br = config.bridge || {};
  const rpc = process.env.SEPOLIA_RPC;
  if (!rpc) { log.info('bridge: SEPOLIA_RPC tidak diset'); return; }

  if (!br?.token?.address || !br?.amount) {
    log.info('bridge: token.address / amount belum dikonfigurasi');
    return;
  }

  const provider = new ethers.JsonRpcProvider(rpc);
  const signer   = wallet.connect(provider);
  const owner    = wallet.address;

  const tokenAddr  = checksumFlexible(br.token.address);
  const spender    = br.spender ? checksumFlexible(br.spender) : null;
  const recipient0 = (br.recipient || '$OWNER').trim();
  const recipient  = (recipient0 === '$OWNER') ? owner : checksumFlexible(recipient0);

  const decimals = Number(br.token.decimals ?? 18);
  const want     = ethers.parseUnits(String(br.amount), decimals);

  try {
    const erc20 = new ethers.Contract(tokenAddr, ERC20_ABI, provider);
    const [balTok, balEth, sym] = await Promise.all([
      erc20.balanceOf(owner),
      provider.getBalance(owner),
      erc20.symbol().catch(()=> 'TOKEN')
    ]);
    log.info(`[balance] native=${ethers.formatEther(balEth)} | ${sym}=${ethers.formatUnits(balTok, decimals)}`);
    if (balTok < want) {
      log.info(`❌ saldo ${sym} kurang: butuh ${ethers.formatUnits(want,decimals)}, punya ${ethers.formatUnits(balTok,decimals)}`);
      return;
    }
  } catch {}

  const wait = br.waitForReceipt ?? true;
  const confs = br.confirmations ?? 1;
  const gasLimit = br.gasLimit ? BigInt(br.gasLimit) : undefined;

  // 0) CUSTOM TX (jika ada)
  if (br.tx?.to && br.tx?.abi && br.tx?.method) {
    const to   = checksumFlexible(br.tx.to);
    const iface= new ethers.Interface(br.tx.abi);
    const vars = { TOKEN: tokenAddr, AMOUNT: want, OWNER: owner, RECIPIENT: recipient };
    const args = materializeArgs(br.tx.args, vars);
    const data = iface.encodeFunctionData(br.tx.method, args);
    const value = br.tx.value ? ethers.parseEther(String(br.tx.value)) : 0n;

    try {
      await ensureAllowance({ signer, tokenAddr, owner, spender: to, wantAmount: want, wait, confs, gasLimit, log });
    } catch (e) { log.info(`approve-error: ${e.reason || e.message || e.code}`); return; }

    log.info(`[bridge] mode=CUSTOM → to=${to}, method=${br.tx.method}`);
    try {
      const tx = await signer.sendTransaction({ to, data, value, ...(gasLimit?{ gasLimit }: {}) });
      log.info(`📝 tx: ${tx.hash}`);
      if (wait) {
        const r = await tx.wait(Math.max(0, Number(confs)));
        log.info(`✅ confirmed (block ${r.blockNumber})`);
      }
    } catch (e) {
      log.info(`❌ custom tx failed → ${e.reason || e.message || e.code}`);
    }
    return;
  }

  // 1) TRANSFER mode
  if (br.useTransfer) {
    if (!spender) { log.info('bridge: useTransfer=true tapi spender kosong'); return; }
    const erc20 = new ethers.Contract(tokenAddr, ERC20_ABI, signer);
    log.info(`[bridge] mode=TRANSFER → to=${spender}, amount=${ethers.formatUnits(want,decimals)}`);
    try {
      const tx = await erc20.transfer(spender, want, ...(gasLimit ? [{ gasLimit }] : []));
      log.info(`📝 tx: ${tx.hash}`);
      if (wait) {
        const r = await tx.wait(Math.max(0, Number(confs)));
        log.info(`✅ confirmed (block ${r.blockNumber})`);
      }
    } catch (e) {
      log.info(`❌ transfer failed → ${e.reason || e.message || e.code}`);
    }
    return;
  }

  // 2) AUTO-DEPOSIT mode (multi-signature probe)
  if (!spender) { log.info('bridge: deposit mode butuh bridge.spender'); return; }

  // beberapa kontrak perlu native fee → config: bridge.nativeFeeEther: "0.001" (opsional)
  const valueNative = br.nativeFeeEther ? ethers.parseEther(String(br.nativeFeeEther)) : 0n;

  // approve dulu ke spender (umum)
  try {
    await ensureAllowance({ signer, tokenAddr, owner, spender, wantAmount: want, wait, confs, gasLimit, log });
  } catch (e) { log.info(`approve-error: ${e.reason || e.message || e.code}`); return; }

  const cands = buildCandidates({ amount: want, recipient });
  log.info(`[bridge] mode=DEPOSIT (auto) → to=${spender}, amount=${ethers.formatUnits(want,decimals)}, recipient=${recipient}${valueNative>0n?`, value=${ethers.formatEther(valueNative)} ETH`:''}`);

  let sent = null;
  for (const cand of cands) {
    try {
      const tx = await tryCallOne({ signer, to: spender, cand, value: valueNative, gasLimit, log });
      sent = { tx, cand };
      break;
    } catch (e) {
      // lanjut ke kandidat berikut
      log.info(`probe ${cand.sig} → revert (${e.reason || e.code || e.message})`);
      continue;
    }
  }

  if (!sent) {
    const wantFallback = (String(br.onRevert || '').toLowerCase() === 'transfer');
    if (!wantFallback) {
      log.info('❌ deposit failed (all candidates reverted). Set bridge.onRevert: transfer atau bridge.useTransfer: true untuk fallback.');
      return;
    }
    try {
      const erc20 = new ethers.Contract(tokenAddr, ERC20_ABI, signer);
      log.info(`[fallback] deposit gagal → transfer ke ${spender}`);
      const tx2 = await erc20.transfer(spender, want, ...(gasLimit ? [{ gasLimit }] : []));
      log.info(`📝 tx: ${tx2.hash}`);
      if (wait) {
        const r2 = await tx2.wait(Math.max(0, Number(confs)));
        log.info(`✅ fallback transfer confirmed (block ${r2.blockNumber})`);
      }
    } catch (e2) {
      log.info(`❌ fallback transfer failed → ${e2.reason || e2.message || e2.code}`);
    }
    return;
  }

  if (wait) {
    const r = await sent.tx.wait(Math.max(0, Number(confs)));
    log.info(`✅ confirmed (block ${r.blockNumber}) via ${sent.cand.sig}`);
  }
}

export default { run };
