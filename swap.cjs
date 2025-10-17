#!/usr/bin/env node
// swap.mjs — ANKR wrap → WANKR → swap WANKR→ztUSD (atau arah lain) dengan guard KETAT arah calldata (harus kandidat A)

import 'dotenv/config';
import { ethers } from 'ethers';

// ---------- utils ----------
const lc = s => String(s||'').toLowerCase();
const strip0x = h => String(h||'').replace(/^0x/i,'');
const with0x = h => h && !String(h).startsWith('0x') ? '0x'+h : String(h);
const isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(String(a||''));
const z = n => '0'.repeat(n);
const noopLog = { mini: (...a)=>console.log(...a) };

function readAddressWord(hexWord) {
  const b = strip0x(hexWord);
  return with0x(b.slice(24)); // last 20 bytes
}

function dumpWords(data, log=noopLog){
  const b=strip0x(data), st=b.length>=8?8:0;
  for(let i=0;i<18 && st+i*64+64<=b.length;i++){
    const w='0x'+b.slice(st+i*64,st+i*64+64);
    log.mini(`[inspect] word#${i} = ${w}${/^0x0{64}$/.test(w)?' (zero)':''}`);
  }
}

function applyPatches({ dataHex, patches=[], owner, log=noopLog }){
  let body = strip0x(dataHex);
  dumpWords('0x'+body, log);
  for(const p of patches){
    const mode = String(p.mode||'').toLowerCase();
    if(mode==='findexact'){
      const old=String(p.old||''), to=String(p.to||'$OWNER');
      const toAddr = to==='$OWNER'? owner : to;
      if(isAddr(old)&&isAddr(toAddr)){
        const find = z(24)+strip0x(old).padStart(40,'0');
        const rep  = z(24)+strip0x(toAddr).padStart(40,'0');
        const re = new RegExp(find,'gi');
        const cnt = (body.match(re)||[]).length;
        if(cnt){ body = body.replace(re, rep); log.mini(`[swap] patch(findExact) ${old} → ${toAddr} (${cnt}x)`); }
      }
    } else if(mode==='auto'){
      const to=String(p.to||'$OWNER'); const toAddr=to==='$OWNER'?owner:to;
      if(!isAddr(toAddr)) continue;
      const idx=Number(p.index ?? p.word ?? p.wordIndex);
      const st=body.length>=8?8:0;
      const putAt=(wi)=>{ const pre=body.slice(0,st+wi*64), post=body.slice(st+wi*64+64);
        log.mini(`[swap] recipientPatch(auto) @word=${wi} 0x${body.slice(st+wi*64+24,st+wi*64+64)} → ${toAddr}`);
        body=pre+(z(24)+strip0x(toAddr).padStart(40,'0'))+post; };
      if(Number.isFinite(idx)&&idx>=0) putAt(idx);
      else{
        const total=Math.floor((body.length-st)/64);
        for(let wi=total-1; wi>=0; wi--){ if(body.slice(st+wi*64,st+wi*64+64)===z(64)){ putAt(wi); break; } }
      }
    }
  }
  return with0x(body);
}

// --- Decoder 0x1679c792 (exactInputSingle-like; alamat ada di word0 & word1; payer di word3) ---
function parse1679(data){
  const b=strip0x(data);
  const w=i=>'0x'+b.slice(8+i*64,8+(i+1)*64);
  const addr=wd=>with0x(wd.slice(-40));
  const A={ tokenIn:addr(w(0)), tokenOut:addr(w(1)), payer:addr(w(3)), amountIn: undefined };
  const B={ tokenIn:addr(w(1)), tokenOut:addr(w(0)), payer:addr(w(3)), amountIn: undefined };
  const slots=[5,9,10,11]; // lokasi lazim amountIn di berbagai aggregator
  for(const i of slots){
    try{ const v=ethers.toBigInt(w(i)); if(v>0n){ if(!A.amountIn) A.amountIn=v; if(!B.amountIn) B.amountIn=v; } }catch{}
  }
  return {A,B};
}

// ---------- ABIs ----------
const ERC20_ABI=[
  'function allowance(address owner,address spender) view returns (uint256)',
  'function approve(address spender,uint256 amount) returns (bool)',
  'function balanceOf(address) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
];
const WETH_LIKE_ABI=[
  'function deposit() payable',
  'function balanceOf(address) view returns (uint256)',
];

// ---------- core helpers ----------
async function ensureAllowance({provider, wallet, token, owner, spender, wantAmount, log=noopLog}){
  const c = new ethers.Contract(token, ERC20_ABI, provider);
  // meta (best effort)
  let sym='???', dec=18;
  try { dec = await c.decimals(); } catch {}
  try { sym = await c.symbol(); } catch {}

  const [bal, cur] = await Promise.all([
    c.balanceOf(owner),
    c.allowance(owner, spender),
  ]);

  log.mini(`[preflight] tokenIn=${token} (${sym}/${dec}) | balance=${bal} | allowance(${spender})=${cur} | need≈${wantAmount}`);

  if(cur >= wantAmount){ log.mini(`[approve] allowance OK (>= need)`); return; }

  // Some tokens require zeroing first
  const cW = c.connect(wallet);
  try{
    const tx1 = await cW.approve(spender, 0);
    log.mini(`[approve] reset→0: ${tx1.hash}`);
    await tx1.wait(1);
  }catch(e){
    log.mini(`[approve] reset→0 skipped: ${e?.shortMessage||e?.message||e}`);
  }

  const tx2 = await cW.approve(spender, ethers.MaxUint256);
  log.mini(`[approve] set→MAX: ${tx2.hash}`);
  await tx2.wait(1);
  const after = await c.allowance(owner, spender);
  log.mini(`[approve] post-allowance=${after}`);
}

async function buildGasOverrides(provider, add=0){
  const fee=await provider.getFeeData();
  const bump=v=>v?(v+v*BigInt(Math.floor(add))/100n):v;
  if(fee.maxFeePerGas && fee.maxPriorityFeePerGas) return {type:2,maxFeePerGas:bump(fee.maxFeePerGas),maxPriorityFeePerGas:bump(fee.maxPriorityFeePerGas)};
  return {type:0, gasPrice:bump(fee.gasPrice ?? 1_000_000_000n)};
}

async function doWrapIfNeeded({ provider, wallet, owner, SW, log=noopLog }) {
  if (!String(SW.wrapFirst).match(/true/i)) return;

  const wtoken = SW.wtoken;
  const value = BigInt(SW.value || '0');

  if (!isAddr(wtoken)) { log.mini('[wrap] skip: wtoken invalid'); return; }
  if (value <= 0n)     { log.mini('[wrap] skip: value=0'); return; }

  const w = new ethers.Contract(wtoken, WETH_LIKE_ABI, provider).connect(wallet);
  const before = await w.balanceOf(owner);
  log.mini(`[wrap] deposit ${value} (ANKR) -> WANKR @ ${wtoken}`);
  const tx = await w.deposit({ value });
  log.mini(`[wrap] tx: ${tx.hash}`);
  const rc = await tx.wait(1);
  const after = await w.balanceOf(owner);
  log.mini(`[wrap] ✅ confirmed in block ${rc.blockNumber} | WANKR balance: ${before} -> ${after}`);
}

// ---------- main ----------
export async function run(ctx){
  const { address: owner, wallet, env={}, config={}, log=noopLog } = ctx;

  const SW = config.swap || {};
  const ROUTER = String(SW.router||'').trim();
  if(!isAddr(ROUTER)){ log.mini('[swap] skip: router missing/invalid'); return; }

  // RPC
  const RPC = env.NEURA_RPC || env.RPC_URL || 'https://testnet.rpc.neuraprotocol.io';
  const provider = new ethers.JsonRpcProvider(RPC);
  const signer = wallet.connect(provider);

  // raw calldata + expected direction
  const raw = String(SW.calldata||'').trim();
  if(!/^0x[0-9a-fA-F]{8,}$/.test(raw)){ log.mini('[swap] skip: calldata kosong/tidak valid'); return; }

  const WANT_IN  = String(SW.tokenIn||'').trim();
  const WANT_OUT = String(SW.tokenOut||'').trim();
  if(!isAddr(WANT_IN)||!isAddr(WANT_OUT)){ log.mini('[swap] config tokenIn/tokenOut wajib diisi'); return; }

  // 0) Wrap (ANKR → WANKR) jika diminta
  await doWrapIfNeeded({ provider, wallet: signer, owner, SW, log });

  // 1) Apply patches
  const data = applyPatches({ dataHex: raw, patches: Array.isArray(SW.patches)?SW.patches:[], owner, log });

  // 2) Ambil subcall pertama jika multicall
  let sub = data;
  if (strip0x(data).slice(0,8).toLowerCase()==='ac9650d8'){
    const iface=new ethers.Interface(['function multicall(bytes[] data)']);
    const arr=iface.decodeFunctionData('multicall',data).data||[];
    if(!arr.length){ log.mini('[mc] kosong'); return; }
    sub=with0x(strip0x(arr[0]));
  }

  // 3) Validasi selector
  if (strip0x(sub).slice(0,8).toLowerCase()!=='1679c792'){
    log.mini('[swap] bukan selector 0x1679c792. Saat ini skrip hanya memvalidasi pola itu.');
    return;
  }

  // 4) Parse kandidat arah
  const {A,B}=parse1679(sub);
  log.mini(`[mc] A: tokenIn=${A.tokenIn} tokenOut=${A.tokenOut} payer=${A.payer} amountIn=${A.amountIn??'(?)'}`);
  log.mini(`[mc] B: tokenIn=${B.tokenIn} tokenOut=${B.tokenOut} payer=${B.payer} amountIn=${B.amountIn??'(?)'}`);

  // 5) PILIH A SAJA (harus cocok arah di calldata). Jika tidak, stop (fail-fast).
  let pick=null;
  if(lc(A.tokenIn)===lc(WANT_IN) && lc(A.tokenOut)===lc(WANT_OUT)) {
    pick = A;
  } else {
    log.mini(`[guard] ❌ Calldata encode arah berbeda!
  Expect A: ${WANT_IN} → ${WANT_OUT}
  Got    A: ${A.tokenIn} → ${A.tokenOut}
  Hint: ambil ulang quote dari dApp untuk arah yang benar, lalu paste ke config.calldata.`);
    return;
  }
  log.mini(`[pick] tokenIn=${pick.tokenIn} tokenOut=${pick.tokenOut} payer=${pick.payer} amountIn=${pick.amountIn ?? '(?)'}`);

  // 6) Payer harus owner
  if(isAddr(pick.payer) && lc(pick.payer)!==lc(owner)){
    log.mini(`[guard] ❌ payer=${pick.payer} ≠ owner ${owner}. Stop.`); return;
  }

  // 7) Cek saldo tokenIn (fail-fast)
  try{
    const erc20=new ethers.Contract(pick.tokenIn,ERC20_ABI,provider);
    const bal=await erc20.balanceOf(owner);
    if(bal===0n){ log.mini(`[guard] ❌ saldo tokenIn=0 (${pick.tokenIn}). Tidak kirim tx.`); return; }
  }catch{}

  // 8) Approve tokenIn → router (dengan reset→0 lalu MAX)
  const need = pick.amountIn && pick.amountIn>0n ? pick.amountIn : (ethers.MaxUint256/4n);
  await ensureAllowance({provider, wallet: signer, token: pick.tokenIn, owner, spender: ROUTER, wantAmount: need, log});

  // 9) Simulasi & estimateGas (decode STF bila gagal)
  const net=await provider.getNetwork();
  log.mini(`\n[rpc] ${RPC} | chainId=${Number(net.chainId)}`);
  log.mini(`[swap] router=${ROUTER}`); log.mini(`[acct] ${owner}`);

  try {
    // gunakan DATA penuh (multicall atau single) karena itu yang akan dieksekusi
    await provider.call({ from: owner, to: ROUTER, data, value: 0n });
  } catch (e) {
    const msg = e?.shortMessage || e?.reason || e?.error?.message || e?.message || String(e);
    log.mini(`[swap] ❌ simulate revert: ${msg}`);
    if (/STF|TRANSFER_FROM_FAILED/i.test(msg)) {
      log.mini(`[hint] "STF" = TransferHelper: TRANSFER_FROM_FAILED → cek:`);
      log.mini(`[hint] 1) Balance tokenIn; 2) Allowance(${ROUTER}); 3) payer==owner; 4) token butuh approve(0) dulu (sudah kita handle).`);
    }
    return;
  }

  let gasLimit;
  try{
    gasLimit=await provider.estimateGas({ from: owner, to: ROUTER, data, value: 0n });
    log.mini(`[swap] simulate OK, estimateGas=${gasLimit}`);
  }catch(e){
    const msg = e?.shortMessage || e?.reason || e?.error?.message || e?.message || String(e);
    log.mini(`[swap] ⚠️ estimateGas gagal: ${msg}`);
    return;
  }

  // 10) Send tx
  const gasOv=await buildGasOverrides(provider, Number(config?.swap?.gas?.addPercent??0));
  const tx=await signer.sendTransaction({to:ROUTER,data,value:0n,gasLimit,...gasOv});
  log.mini(`[swap] tx: ${tx.hash}`);
  if(config?.swap?.waitForReceipt!==false){
    const rc=await tx.wait(Number(config?.swap?.confirmations??1)||1);
    log.mini(`[swap] ✅ confirmed in block ${rc.blockNumber}`);
  }
}

export default { run };

// ---------- Optional: CLI quick runner ----------
// Jalankan: OWNER_PK=0x... node swap.mjs
if (import.meta.url === `file://${process.argv[1]}`) {
  (async () => {
    const OWNER_PK = process.env.OWNER_PK || process.env.PRIVATE_KEY;
    if (!OWNER_PK) {
      console.error('Env OWNER_PK/PRIVATE_KEY kosong.');
      process.exit(1);
    }
    const wallet = new ethers.Wallet(OWNER_PK);
    const owner = await wallet.getAddress();

    // Example config minimal — ganti sesuai kebutuhanmu:
    const config = {
      swap: {
        router: process.env.ROUTER || '0x5AeFBA317BAba46EAF98Fd6f381d07673bcA6467',
        // HARUS: calldata arah WANKR→ztUSD (atau sesuai targetmu)
        calldata: process.env.CALLDATA || '0x',
        tokenIn:  (process.env.TOKEN_IN  || '0xbd833b6ecc30caeabf81db18bb0f1e00c6997e7a').trim(), // WANKR
        tokenOut: (process.env.TOKEN_OUT || '0x9423c6c914857e6daaace3b585f4640231505128').trim(), // ztUSD
        // Step wrap (opsional, set true untuk ANKR→WANKR)
        wrapFirst: String(process.env.WRAP_FIRST||'false'),
        wrapRequired: String(process.env.WRAP_REQUIRED||'true'),
        nativePay: String(process.env.NATIVE_PAY||'true'),
        wtoken: (process.env.WTOKEN||'0xbd833b6ecc30caeabf81db18bb0f1e00c6997e7a').trim(), // WANKR
        value: String(process.env.WRAP_VALUE||'0'), // jumlah ANKR untuk deposit()
        gas: { addPercent: Number(process.env.GAS_ADD_PERCENT||5) },
        patches: [
          { mode:'findExact', old:(process.env.OLD_PAYER||'0xDc91FDbf1F8E5F470788CeBaC7e3B13DD63bd4bC'), to:'$OWNER' },
          { mode:'auto', index: Number.isFinite(Number(process.env.RECIPIENT_WORD_INDEX)) ? Number(process.env.RECIPIENT_WORD_INDEX) : 13 },
        ],
      }
    };

    const ctx = {
      address: owner,
      wallet,
      env: process.env,
      config,
      log: { mini: (...a)=>console.log(...a) },
    };

    await run(ctx);
  })().catch(e=>{ console.error(e); process.exit(1); });
}
