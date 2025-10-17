#!/usr/bin/env node
// multiroute-swap.mjs — routes + useRouter + robust wrap + resim-before-send + runAll/times + log by config.log.level
//
// Log Levels (ambil dari config.log.level):
// - silent     → hanya log inti (multi start, success, fail reason).
// - debugApi   → tambah log approve/simulate/estimate/tx hash.
// - debugAll   → verbose penuh + inspect dump + detail patch.
//
// Fitur:
// - routes[] bernama; useRouter: "name", "name1,name2", "both/all"
// - strictAOnly & disallowForceSend
// - resimulateBeforeSend (global/rute)
// - wrap ANKR→WANKR (NON-BLOCKING; kalau gagal lanjut cek saldo & swap)
// - patch recipient/payer, approve reset→MAX, simulate, estimate, send
// - dynamicFixes: subIndex, deadlinePlus, minOutWord/hardcodeMinOut, amountInFromBalance
// - amount override: amount: "max" | "<uint>" (patch ke calldata & allowance)
// - fee guard: require native balance >= minNativeForFee (default 0.1 ANKR)

import 'dotenv/config';
import { ethers } from 'ethers';

// ---------- logger ----------
function makeLogger(level='silent') {
  const lv = String(level||'silent').toLowerCase();
  const flags = {
    silent: lv === 'silent',
    debugApi: lv === 'debugapi',
    debugAll: lv === 'debugall',
  };
  const core  = (...a)=>console.log(...a);
  const debug = (...a)=>{ if (flags.debugApi || flags.debugAll) console.log(...a); };
  const verb  = (...a)=>{ if (flags.debugAll) console.log(...a); }; // for inspect-level
  return { core, debug, verb, flags };
}

// ---------- utils ----------
const lc = s => String(s||'').toLowerCase();
const strip0x = h => String(h||'').replace(/^0x/i,'');
const with0x = h => h && !String(h).startsWith('0x') ? '0x'+h : String(h);
const isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(String(a||''));
const z = n => '0'.repeat(n);
const noopLog = { core:()=>{}, debug:()=>{}, verb:()=>{}, flags:{silent:true,debugApi:false,debugAll:false} };

function dumpWords(data, log=noopLog){
  const b=strip0x(data), st=b.length>=8?8:0;
  for(let i=0;i<22 && st+i*64+64<=b.length;i++){
    const w='0x'+b.slice(st+i*64,st+i*64+64);
    log.verb(`[inspect] word#${i} = ${w}${/^0x0{64}$/.test(w)?' (zero)':''}`);
  }
}
function getWords(dataHex){
  const b=strip0x(dataHex), st=b.length>=8?8:0;
  const arr=[];
  for(let i=0; st+i*64+64<=b.length; i++){
    arr.push('0x'+b.slice(st+i*64,st+i*64+64));
  }
  return { words: arr, start: st, raw: b };
}
function writeWord(body, wi, hex32){
  return body.slice(0,wi*64)+strip0x(hex32).padStart(64,'0')+body.slice(wi*64+64);
}

function applyPatches({ dataHex, patches=[], owner, log=noopLog }){
  let body = strip0x(dataHex);
  if (log.flags.debugAll) dumpWords('0x'+body, log);
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
        if(cnt){ body = body.replace(re, rep); log.verb(`[patch] findExact ${old} → ${toAddr} (${cnt}x)`); }
      }
    } else if(mode==='auto'){
      const to=String(p.to||'$OWNER'); const toAddr=to==='$OWNER'?owner:to;
      if(!isAddr(toAddr)) continue;
      const idx=Number(p.index ?? p.word ?? p.wordIndex);
      const { start:st, raw } = { start: body.length>=8?8:0, raw: body };
      const putAt=(wi)=>{
        const before = raw.slice(0,st+wi*64);
        const cur    = raw.slice(st+wi*64,st+wi*64+64);
        const after  = raw.slice(st+wi*64+64);
        log.verb(`[patch] recipient(auto) @word=${wi} 0x${cur.slice(24)} → ${toAddr}`);
        body = before + (z(24)+strip0x(toAddr).padStart(40,'0')) + after;
      };
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
  const A={ tokenIn:addr(w(0)), tokenOut:addr(w(1)), payer:addr(w(3)), amountIn: undefined, amountWord: undefined };
  const B={ tokenIn:addr(w(1)), tokenOut:addr(w(0)), payer:addr(w(3)), amountIn: undefined, amountWord: undefined };
  const slots=[5,9,10,11]; // lokasi lazim amountIn di berbagai aggregator
  for(const i of slots){
    try{
      const v=ethers.toBigInt(w(i));
      if(v>0n){
        if(!A.amountIn){ A.amountIn=v; A.amountWord=i; }
        if(!B.amountIn){ B.amountIn=v; B.amountWord=i; }
      }
    }catch{}
  }
  return {A,B, slots};
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
  let sym='???', dec=18;
  try { dec = await c.decimals(); } catch {}
  try { sym = await c.symbol(); } catch {}
  const [bal, cur] = await Promise.all([ c.balanceOf(owner), c.allowance(owner, spender) ]);
  log.debug(`[preflight] tokenIn=${token} (${sym}/${dec}) | balance=${bal} | allowance(${spender})=${cur} | need≈${wantAmount}`);
  if(cur >= wantAmount){ log.debug(`[approve] allowance OK (>= need)`); return; }
  const cW = c.connect(wallet);
  try{
    const tx1 = await cW.approve(spender, 0);
    log.debug(`[approve] reset→0: ${tx1.hash}`); await tx1.wait(1);
  }catch(e){ log.debug(`[approve] reset→0 skipped: ${e?.shortMessage||e?.message||e}`); }
  const tx2 = await cW.approve(spender, ethers.MaxUint256);
  log.debug(`[approve] set→MAX: ${tx2.hash}`); await tx2.wait(1);
  const after = await c.allowance(owner, spender);
  log.debug(`[approve] post-allowance=${after}`);
}

async function buildGasOverrides(provider, add=0){
  const fee=await provider.getFeeData();
  const bump=v=>v?(v+v*BigInt(Math.floor(add))/100n):v;
  if(fee.maxFeePerGas && fee.maxPriorityFeePerGas) return {type:2,maxFeePerGas:bump(fee.maxFeePerGas),maxPriorityFeePerGas:bump(fee.maxPriorityFeePerGas)};
  return {type:0, gasPrice:bump(fee.gasPrice ?? 1_000_000_000n)};
}

// Wrap non-blocking: kalau gagal, hanya log dan lanjut
async function doWrapIfNeeded({ provider, wallet, owner, SW, log=noopLog }) {
  if (!String(SW.wrapFirst).match(/true/i)) return;
  const wtoken = SW.wtoken;
  const value = BigInt(SW.value || '0');
  if (!isAddr(wtoken)) { log.debug('[wrap] skip: wtoken invalid'); return; }
  if (value <= 0n)     { log.debug('[wrap] skip: value=0'); return; }

  const w = new ethers.Contract(wtoken, WETH_LIKE_ABI, provider).connect(wallet);
  const before = await w.balanceOf(owner);
  log.debug(`[wrap] deposit ${value} (ANKR) -> WANKR @ ${wtoken}`);

  try {
    const tx = await w.deposit({ value });
    log.debug(`[wrap] tx: ${tx.hash}`);
    const rc = await tx.wait(1);
    const after = await w.balanceOf(owner);
    log.debug(`[wrap] ✅ confirmed in block ${rc.blockNumber} | WANKR balance: ${before} -> ${after}`);
  } catch (e) {
    const msg = e?.shortMessage || e?.reason || e?.message || String(e);
    log.debug(`[wrap] warn: deposit() failed via helper: ${msg}`);
    // fallback
    try {
      const gasLimit = Number(SW.wrapGasLimit || 120000);
      const tx = await wallet.sendTransaction({ to: wtoken, data: '0xd0e30db0', value, gasLimit });
      log.debug(`[wrap] fallback tx: ${tx.hash}`);
      const rc = await tx.wait(1);
      const after = await w.balanceOf(owner);
      log.debug(`[wrap] ✅ fallback confirmed in block ${rc.blockNumber} | WANKR balance: ${before} -> ${after}`);
    } catch (e2) {
      const msg2 = e2?.shortMessage || e2?.reason || e2?.message || String(e2);
      log.debug(`[wrap] ❌ fallback failed: ${msg2}`);
      log.debug(`[wrap] ⚠️ gagal → lanjut ke swap (non-blocking)`);
    }
  }
}

// ---------- dynamic fixes (deadline/minOut/amountIn from balance) ----------
async function applyDynamicFixes({ dataHex, SW, owner, provider, log=noopLog }){
  // handle multicall subIndex
  let outer = strip0x(dataHex);
  const isMc = outer.slice(0,8).toLowerCase()==='ac9650d8';
  if (!isMc && !SW?.dynamicFixes) return with0x(outer);

  if (isMc) {
    const iface=new ethers.Interface(['function multicall(bytes[] data)']);
    const arr=iface.decodeFunctionData('multicall', with0x(outer)).data||[];
    const subIdx = Number(SW?.dynamicFixes?.subIndex ?? 0);
    if (arr[subIdx]) {
      arr[subIdx] = await applyDynamicFixesCore({ subData: arr[subIdx], SW, owner, provider, log });
      const newData = iface.encodeFunctionData('multicall',[arr]);
      return newData;
    }
    return with0x(outer);
  } else {
    // not multicall, but dynamicFixes needed?
    return await applyDynamicFixesCore({ subData: with0x(outer), SW, owner, provider, log });
  }
}

async function applyDynamicFixesCore({ subData, SW, owner, provider, log }){
  // only for 0x1679c792
  const sel = strip0x(subData).slice(0,8).toLowerCase();
  if (sel!=='1679c792') return subData;

  let body = strip0x(subData);
  const { words } = getWords(subData);

  // deadline
  const dlWord = Number(SW?.dynamicFixes?.deadlineWord);
  const dlPlus = Number(SW?.dynamicFixes?.deadlinePlus || 300);
  if (Number.isFinite(dlWord) && dlWord>=0) {
    const blk = await provider.getBlock('latest');
    const ts = BigInt((blk?.timestamp ?? Math.floor(Date.now()/1000)) + dlPlus);
    const put = '0x'+z(56)+ts.toString(16);
    const head = body.slice(0,8);
    let tail  = body.slice(8);
    tail = writeWord(tail, dlWord, put);
    body = head+tail;
    log.debug(`[dyn] set deadline(word ${dlWord}) = ${ts}`);
  }

  // minOut
  const minOutWord = Number(SW?.dynamicFixes?.minOutWord);
  if (Number.isFinite(minOutWord) && minOutWord>=0) {
    const val = BigInt(SW?.dynamicFixes?.hardcodeMinOut ?? '0');
    const put = '0x'+val.toString(16).padStart(64,'0');
    const head = body.slice(0,8);
    let tail  = body.slice(8);
    tail = writeWord(tail, minOutWord, put);
    body = head+tail;
    log.debug(`[dyn] set minOut(word ${minOutWord}) = ${val}`);
  }

  // amountIn from balance / amount override
  const {A,B,slots} = parse1679(with0x(body));
  // tentukan arah berdasarkan config
  const WANT_IN  = String(SW.tokenIn||'').trim();
  const WANT_OUT = String(SW.tokenOut||'').trim();
  let pick=null;
  if(lc(A.tokenIn)===lc(WANT_IN) && lc(A.tokenOut)===lc(WANT_OUT)) pick=A;
  else if(lc(B.tokenIn)===lc(WANT_IN) && lc(B.tokenOut)===lc(WANT_OUT)) pick=B;

  // balance fetch kalau perlu
  let overrideAmount = null;
  const amountModeMax = String(SW?.amount||'').toLowerCase()==='max';
  if (SW?.dynamicFixes?.amountInFromBalance || amountModeMax || (SW?.amount && /^\d+$/.test(String(SW.amount)))) {
    // kalau user set angka, pakai itu; kalau 'max' pakai balance tokenIn
    if (amountModeMax) {
      try {
        const c = new ethers.Contract(WANT_IN, ERC20_ABI, provider);
        overrideAmount = await c.balanceOf(owner);
      } catch {}
    } else if (SW?.amount && /^\d+$/.test(String(SW.amount))) {
      try { overrideAmount = ethers.toBigInt(String(SW.amount)); } catch {}
    }
  }

  if (overrideAmount!==null && pick?.amountWord!=null) {
    const head = body.slice(0,8);
    let  tail  = body.slice(8);
    const put  = '0x'+overrideAmount.toString(16).padStart(64,'0');
    tail = writeWord(tail, pick.amountWord, put);
    body = head+tail;
    log.debug(`[dyn] set amountIn(word ${pick.amountWord}) = ${overrideAmount}`);
  }

  return with0x(body);
}

// ---------- single-route runner ----------
async function runOneRoute({ ctx, SW, owner, signer, provider, globalFlags }){
  const log = ctx.log || noopLog;
  const ROUTER = String(SW.router||globalFlags?.DEFAULT_ROUTER||'').trim();
  if(!isAddr(ROUTER)){ log.core(`[swap] skip: router missing/invalid`); return { ok:false, reason:'invalid router' }; }

  const STRICT_A_ONLY = !!(globalFlags?.STRICT_A_ONLY);
  const DISALLOW_FORCE = globalFlags?.DISALLOW_FORCE !== false; // default true
  const RESIM_BEFORE = !!(globalFlags?.RESIM_BEFORE);
  const MIN_NATIVE = BigInt(ethers.parseEther(String(globalFlags?.MIN_NATIVE_FOR_FEE ?? SW?.minNativeForFee ?? '0.1'))); // 0.1 ANKR default

  // 0) Wrap jika diminta (non-blocking)
  try { await doWrapIfNeeded({ provider, wallet: signer, owner, SW, log }); } catch {}

  // 1) Ambil & patch calldata dasar
  const raw0 = String(SW.calldata||'').trim();
  if(!/^0x[0-9a-fA-F]{8,}$/.test(raw0)){ log.core('[swap] skip: calldata kosong/tidak valid'); return { ok:false, reason:'invalid calldata' }; }
  let data = applyPatches({ dataHex: raw0, patches: Array.isArray(SW.patches)?SW.patches:[], owner, log });

  // 1b) Dynamic fixes (deadline / minOut / amountIn)
  data = await applyDynamicFixes({ dataHex: data, SW, owner, provider, log });

  // 2) Subcall jika multicall → gunakan sub untuk parse
  let sub = data;
  if (strip0x(data).slice(0,8).toLowerCase()==='ac9650d8'){
    const iface=new ethers.Interface(['function multicall(bytes[] data)']);
    const arr=iface.decodeFunctionData('multicall',data).data||[];
    if(!arr.length){ log.core('[mc] kosong'); return { ok:false, reason:'empty multicall' }; }
    const subIdx = Number(SW?.dynamicFixes?.subIndex ?? 0);
    sub=with0x(strip0x(arr[subIdx] ?? arr[0]));
  }

  // 3) Validasi selector
  if (strip0x(sub).slice(0,8).toLowerCase()!=='1679c792'){
    log.debug('[swap] bukan selector 0x1679c792 (saat ini hanya pola itu).');
    return { ok:false, reason:'wrong selector' };
  }

  // 4) Parse kandidat
  const WANT_IN  = String(SW.tokenIn||'').trim();
  const WANT_OUT = String(SW.tokenOut||'').trim();
  if(!isAddr(WANT_IN)||!isAddr(WANT_OUT)){ log.core('[swap] tokenIn/tokenOut wajib diisi'); return { ok:false, reason:'missing tokenIn/out' }; }

  const {A,B}=parse1679(sub);
  log.debug(`[route:${SW.name||'-'}] A: ${A.tokenIn}→${A.tokenOut} payer=${A.payer} amountIn=${A.amountIn??'(?)'}`);
  log.debug(`[route:${SW.name||'-'}] B: ${B.tokenIn}→${B.tokenOut} payer=${B.payer} amountIn=${B.amountIn??'(?)'}`);

  let pick=null;
  if(lc(A.tokenIn)===lc(WANT_IN) && lc(A.tokenOut)===lc(WANT_OUT)) pick=A;
  else if (!STRICT_A_ONLY && lc(B.tokenIn)===lc(WANT_IN) && lc(B.tokenOut)===lc(WANT_OUT)) pick=B;

  if(!pick){
    const why = STRICT_A_ONLY
      ? 'strictAOnly aktif: hanya menerima arah kandidat A.'
      : 'calldata tidak cocok dengan tokenIn/tokenOut.';
    log.core(`[guard] direction mismatch: ${why}`);
    return { ok:false, reason:'direction mismatch' };
  }
  log.debug(`[pick:${SW.name||'-'}] tokenIn=${pick.tokenIn} tokenOut=${pick.tokenOut} payer=${pick.payer} amountIn=${pick.amountIn ?? '(?)'}`);

  // 5) Payer harus owner
  if(isAddr(pick.payer) && lc(pick.payer)!==lc(owner)){
    log.core(`[guard] payer mismatch: ${pick.payer} ≠ owner ${owner}`);
    return { ok:false, reason:'payer mismatch' };
  }

  // 6) Cek saldo tokenIn (dan siapkan amount=MAX bila diminta)
  let tokenBal = 0n;
  try{
    const erc20=new ethers.Contract(pick.tokenIn,ERC20_ABI,provider);
    tokenBal=await erc20.balanceOf(owner);
    if(tokenBal===0n){ log.core(`[guard] saldo tokenIn=0 ${pick.tokenIn}`); return { ok:false, reason:'zero balance' }; }
  }catch{}

  // 7) Fee guard (native for gas) — minimal 0.1 ANKR (bisa override via minNativeForFee)
  try {
    const nativeBal = await provider.getBalance(owner);
    if (nativeBal < MIN_NATIVE) {
      log.core(`[guard] native balance ${nativeBal} < minNativeForFee ${MIN_NATIVE} (ANKR wei)`);
      return { ok:false, reason:'low native for fee' };
    }
  } catch {}

  // 8) Approve — hitung wantAmount (pakai override amount jika "max")
  let wantAmount = pick.amountIn && pick.amountIn>0n ? pick.amountIn : (ethers.MaxUint256/4n);
  if (String(SW?.amount||'').toLowerCase()==='max') wantAmount = tokenBal;
  if (SW?.amount && /^\d+$/.test(String(SW.amount))) {
    try { wantAmount = ethers.toBigInt(String(SW.amount)); } catch {}
  }
  await ensureAllowance({provider, wallet: signer, token: pick.tokenIn, owner, spender: ROUTER, wantAmount, log});

  // 9) Simulasi & estimate
  const net=await provider.getNetwork();
  log.debug(`[rpc] chainId=${Number(net.chainId)} | router=${ROUTER} | acct=${owner} | route=${SW.name||'-'}`);

  try {
    await provider.call({ from: owner, to: ROUTER, data, value: 0n });
  } catch (e) {
    const msg = e?.shortMessage || e?.reason || e?.error?.message || e?.message || String(e);
    log.debug(`[swap:${SW.name||'-'}] simulate revert: ${msg}`);
    if (DISALLOW_FORCE) return { ok:false, reason:'simulate revert' };
  }

  let gasLimit;
  try{
    gasLimit=await provider.estimateGas({ from: owner, to: ROUTER, data, value: 0n });
    log.debug(`[swap:${SW.name||'-'}] estimateGas=${gasLimit}`);
  }catch(e){
    const msg = e?.shortMessage || e?.reason || e?.error?.message || e?.message || String(e);
    log.debug(`[swap:${SW.name||'-'}] estimateGas failed: ${msg}`);
    if (DISALLOW_FORCE) return { ok:false, reason:'estimateGas failed' };
  }

  // 9b) Quick fee sanity: coba kalkulasi kasar biar tidak over
  try{
    const fee=await provider.getFeeData();
    const maxFeePerGas = fee.maxFeePerGas ?? fee.gasPrice ?? 0n;
    const nativeBal = await provider.getBalance(owner);
    const estimatedCost = (gasLimit ?? 200000n) * (maxFeePerGas||1n);
    if (nativeBal < estimatedCost) {
      log.core(`[guard] native balance < estimated tx fee (${estimatedCost})`);
      return { ok:false, reason:'insufficient gas fee' };
    }
  }catch{}

  // 10) Resimulate tepat sebelum kirim (opsional)
  if (RESIM_BEFORE) {
    try {
      await provider.call({ from: owner, to: ROUTER, data, value: 0n });
    } catch {
      log.core(`[swap:${SW.name||'-'}] resimulate-before-send revert`);
      return { ok:false, reason:'resimulate revert' };
    }
  }

  // 11) Send & receipt
  let tx;
  try {
    const gasOv=await buildGasOverrides(provider, Number(SW?.gas?.addPercent??0));
    tx = await signer.sendTransaction({to:ROUTER,data,value:0n,gasLimit, ...gasOv});
    log.debug(`[swap:${SW.name||'-'}] tx: ${tx.hash}`);
  } catch {
    log.core(`[swap:${SW.name||'-'}] sendTransaction failed`);
    return { ok:false, reason:'send failed' };
  }

  if(SW?.waitForReceipt!==false){
    try {
      const rc=await tx.wait(Number(SW?.confirmations??1)||1);
      if (rc.status !== 1) {
        log.core(`[swap:${SW.name||'-'}] on-chain revert (status=0)`);
        return { ok:false, reason:'onchain revert' };
      }
      log.core(`[swap:${SW.name||'-'}] ✅ confirmed tx=${tx.hash} block=${rc.blockNumber}`);
    } catch {
      log.core(`[swap:${SW.name||'-'}] wait receipt failed`);
      return { ok:false, reason:'receipt failed' };
    }
  }
  return { ok:true, txHash: tx.hash };
}

// ---------- main (multi-route) ----------
export async function run(ctx){
  const { address: owner, wallet, env={}, config={} } = ctx;

  // logger by config.log.level
  const level = config?.log?.level || 'silent';
  const log = makeLogger(level);

  const RPC = env.NEURA_RPC || env.RPC_URL || 'https://testnet.rpc.neuraprotocol.io';
  const provider = new ethers.JsonRpcProvider(RPC);
  const signer = wallet.connect(provider);

  const SW = config.swap || {};

  const STRICT_A_ONLY = !!SW.strictAOnly;
  const DISALLOW_FORCE = SW.disallowForceSend !== false; // default true

  // kontrol eksekusi
  const RUN_ALL = String(SW.runAll ?? 'true') !== 'false';
  const STOP_ON_FIRST_SUCCESS = String(SW.stopOnFirstSuccess ?? 'false') === 'true';

  // Normalize routes:
  let routes = [];
  if (Array.isArray(SW.routes) && SW.routes.length) {
    routes = SW.routes.map(r => ({ ...(r||{}), name: r?.name || '-' }));
  } else {
    routes = [{ ...SW, name: SW.name || '-' }];
  }

  // Decide which routes to run:
  let orderNames = [];
  const rawUse = String(SW.useRouter||'').trim();
  if (!rawUse || lc(rawUse)==='both' || lc(rawUse)==='all') {
    orderNames = routes.map(r => r.name);
  } else {
    orderNames = rawUse.split(',').map(s => s.trim()).filter(Boolean);
  }

  // Filter routes by names (preserving order)
  const selected = [];
  for (const nm of orderNames) {
    const r = routes.find(x => String(x.name)===nm);
    if (r) selected.push(r);
  }
  const runList = selected.length ? selected : routes;

  // LOG INTI: mulai multi-run
  log.core(`[multi] useRouter="${rawUse||'all'}" → running ${runList.map(r=>r.name).join(', ')}`);

  let successCount = 0;
  let lastError = null;

  for (const r of runList) {
    const times = Math.max(1, Number(r.times||1));
    for (let k=0; k<times; k++){
      const res = await runOneRoute({
        ctx: { ...ctx, log },
        SW: r, owner, signer, provider,
        globalFlags: {
          STRICT_A_ONLY,
          DISALLOW_FORCE,
          RESIM_BEFORE: !!r.resimulateBeforeSend || !!(config.swap?.resimulateBeforeSend),
          MIN_NATIVE_FOR_FEE: SW?.minNativeForFee ?? config?.swap?.minNativeForFee ?? '0.1',
          DEFAULT_ROUTER: r?.router || SW?.router,
        }
      });

      if (res.ok) {
        successCount++;
        log.core(`[multi] success "${r.name}" run#${k+1} tx=${res.txHash}`);
        if (!RUN_ALL || STOP_ON_FIRST_SUCCESS) return;
      } else {
        lastError = res.reason || 'unknown';
        log.core(`[multi] route "${r.name}" run#${k+1} failed: ${res.reason}`);
      }
    }
  }

  if (successCount > 0) {
    log.core(`[multi] done: ${successCount} success`);
  } else {
    log.core(`[multi] all routes failed${lastError?` (last=${lastError})`:''}`);
  }
}

export default { run };

// ---------- Optional: CLI quick runner ----------
if (import.meta.url === `file://${process.argv[1]}`) {
  (async () => {
    const OWNER_PK = process.env.OWNER_PK || process.env.PRIVATE_KEY;
    if (!OWNER_PK) { console.error('Env OWNER_PK/PRIVATE_KEY kosong.'); process.exit(1); }
    const wallet = new ethers.Wallet(OWNER_PK);
    const owner = await wallet.getAddress();

    const config = {
      log: { level: process.env.LOG_LEVEL || 'silent' },
      swap: {
        useRouter: process.env.USE_ROUTER || 'both',
        strictAOnly: String(process.env.STRICT_A_ONLY||'true')==='true',
        disallowForceSend: String(process.env.DISALLOW_FORCE_SEND||'true')!=='false',
        resimulateBeforeSend: String(process.env.RESIM_BEFORE||'true')==='true',
        wrapGasLimit: Number(process.env.WRAP_GAS_LIMIT||120000),

        // fee guard
        minNativeForFee: process.env.MIN_NATIVE_FOR_FEE || '0.1', // ANKR

        // eksekusi
        runAll: String(process.env.RUN_ALL ?? 'true') !== 'false',
        stopOnFirstSuccess: String(process.env.STOP_ON_FIRST_SUCCESS ?? 'false') === 'true',

        routes: [
          // isi YAML kamu
        ]
      }
    };

    const ctx = { address: owner, wallet, env: process.env, config };
    await run(ctx);
  })().catch(e=>{ console.error(e); process.exit(1); });
}
