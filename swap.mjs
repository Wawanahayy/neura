#!/usr/bin/env node
// multiroute-swap.mjs — multi-route swap with autoback, robust wrap, retries, quiet/debug logs
// Patch: RPC retry helpers (call/estimate/receipt) to avoid -32064 "Proxy error"
// Patch+: Fee Top-Up Guard (ensure ANKR >= minNative); skip safely if zero balances
// Patch++: JSON-RPC BigInt serialize fix (no raw BigInt in provider.send payloads)
// Patch+++: GasLimit headroom (limitBumpPercent/limitAdd/minGasLimit) + back-route bump + typo fix

import 'dotenv/config';
import { ethers } from 'ethers';

// ---------- utils ----------
const lc = s => String(s||'').toLowerCase();
const strip0x = h => String(h||'').replace(/^0x/i,'');
const with0x = h => h && !String(h).startsWith('0x') ? '0x'+h : String(h);
const isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(String(a||''));
const z = n => '0'.repeat(n);
const sleep = (ms)=> new Promise(r=>setTimeout(r, Math.max(0, Number(ms)||0)));
const truthy = (v) => {
  const s = String(v ?? '').trim().toLowerCase();
  return v === true || s === 'true' || s === 'on' || s === '1' || s === 'yes';
};
const shortHash = (h, n=5) => {
  const b = strip0x(h||'');
  if (!b) return '';
  return '0x' + b.slice(0, n) + '…';
};
const get = (o,p,d)=>{ try{ return p.split('.').reduce((x,k)=> (x&&k in x)?x[k]:undefined,o) ?? d; }catch{ return d; } };

// ---------- logging skeleton ----------
const noopLog = {
  mini: (...a)=>console.log(...a),
  essential: (...a)=>console.log(...a),
  dbg:  (..._a)=>{},
  insp: (..._a)=>{},
  mode: 'silent'
};

// ---------- RPC retry helpers ----------
const isTransientRpcError = (e) => {
  const msg = String(e?.shortMessage || e?.message || '');
  const code = e?.code ?? e?.error?.code;
  const emsg = String(e?.error?.message || '');
  return (
    code === -32064 || /Proxy error/i.test(msg) || /Proxy error/i.test(emsg) ||
    /ETIMEDOUT|ECONNRESET|ENETUNREACH|EAI_AGAIN/i.test(msg) ||
    /could not coalesce/i.test(msg)
  );
};

// 🆕 encode tx object to avoid raw BigInt in JSON-RPC
function encodeTxObjForRpc({ from, to, data, value }) {
  const tx = {};
  if (from) tx.from = from;
  if (to)   tx.to   = to;
  if (data) tx.data = data;

  // only include value if > 0, and encode as hex string
  if (typeof value === 'bigint') {
    if (value > 0n) tx.value = ethers.toBeHex(value);
  } else if (value != null) {
    try {
      const bn = BigInt(value);
      if (bn > 0n) tx.value = ethers.toBeHex(bn);
    } catch {
      // ignore non-numeric
    }
  }
  return tx;
}

async function providerCallWithRetry(provider, method, params = [], {
  tries = 6, base = 600, backoff = 1.9, jitter = 250, log = noopLog
} = {}) {
  let delay = base;
  for (let t = 1; t <= tries; t++) {
    try { return await provider.send(method, params); }
    catch (e) {
      if (!isTransientRpcError(e) || t === tries) throw e;
      const wait = delay + Math.floor(Math.random() * jitter);
      log.essential?.(`[retry rpc] ${method} ${t}/${tries-1} · ${e?.error?.message || e.message} · wait ${wait}ms`);
      await sleep(wait);
      delay = Math.floor(delay * backoff);
    }
  }
}

async function callWithRetry(provider, req, opts) {
  const tx = encodeTxObjForRpc(req || {});
  return providerCallWithRetry(provider, 'eth_call', [tx, 'latest'], opts);
}

async function estimateGasWithRetry(provider, txReq, opts) {
  const tx = encodeTxObjForRpc(txReq || {});
  return providerCallWithRetry(provider, 'eth_estimateGas', [tx], opts);
}

async function getReceiptWithRetry(provider, txHash, opts) {
  return providerCallWithRetry(provider, 'eth_getTransactionReceipt', [txHash], opts);
}

async function waitForReceiptSafe(provider, txHash, {
  pollMs = 4000, totalMs = 300_000, log = noopLog,
  tries = 4, base = 500, backoff = 1.9, jitter = 250
} = {}) {
  const start = Date.now();
  while (Date.now() - start < totalMs) {
    try {
      const rc = await getReceiptWithRetry(provider, txHash, { tries, base, backoff, jitter, log });
      if (rc) return rc; // null → belum mined
    } catch (e) {
      if (!isTransientRpcError(e)) throw e;
      log.essential?.(`[retry receipt] ${e?.error?.message || e.message}`);
    }
    await sleep(pollMs);
  }
  throw new Error('waitForReceiptSafe timeout');
}

// ---------- word dump ----------
function dumpWords(data, log=noopLog){
  const b=strip0x(data), st=b.length>=8?8:0;
  for(let i=0;i<22 && st+i*64+64<=b.length;i++){
    const w='0x'+b.slice(st+i*64,st+i*64+64);
    log.insp(`[inspect] word#${i} = ${w}${/^0x0{64}$/.test(w)?' (zero)':''}`);
  }
}

// ---------- calldata patch ----------
function applyPatches({ dataHex, patches=[], owner, log=noopLog, debugAll=false }){
  let body = strip0x(dataHex);
  if (debugAll) dumpWords('0x'+body, log);
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
        if(cnt){ body = body.replace(re, rep); log.dbg(`[patch] findExact ${old} → ${toAddr} (${cnt}x)`); }
      }
    } else if(mode==='auto'){
      const to=String(p.to||'$OWNER'); const toAddr=to==='$OWNER'?owner:to;
      if(!isAddr(toAddr)) continue;
      const idx=Number(p.index ?? p.word ?? p.wordIndex);
      const st=body.length>=8?8:0;
      const putAt=(wi)=>{ const pre=body.slice(0,st+wi*64), post=body.slice(st+wi*64+64);
        log.dbg(`[patch] recipient(auto) @word=${wi} 0x${body.slice(st+wi*64+24,st+wi*64+64)} → ${toAddr}`);
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

// ---------- helpers for amount:max ----------
function setWordAt(dataHex, wordIndex, valueBig) {
  const b = strip0x(dataHex);
  const st = b.length>=8?8:0;
  const pre = b.slice(0, st + wordIndex*64);
  const post = b.slice(st + wordIndex*64 + 64);
  const vhex = strip0x(ethers.toBeHex(valueBig)).padStart(64,'0');
  return with0x(pre + vhex + post);
}

function getWord(dataHex, wordIndex){
  const b = strip0x(dataHex);
  const st = b.length>=8?8:0;
  return with0x(b.slice(st + wordIndex*64, st + (wordIndex+1)*64));
}

// --- Decoder 0x1679c792 (exactInputSingle-like; addr in word0 & word1; payer in word3) ---
function parse1679(data){
  const b=strip0x(data);
  const w=i=>'0x'+b.slice(8+i*64,8+(i+1)*64);
  const addr=wd=>with0x(wd.slice(-40));
  const A={ tokenIn:addr(w(0)), tokenOut:addr(w(1)), payer:addr(w(3)), amountIn: undefined };
  const B={ tokenIn:addr(w(1)), tokenOut:addr(w(0)), payer:addr(w(3)), amountIn: undefined };
  const slots=[5,9,10,11];
  for(const i of slots){
    try{ const v=ethers.toBigInt(w(i)); if(v>0n){ if(!A.amountIn) A.amountIn=v; if(!B.amountIn) B.amountIn=v; } }catch{}
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
const WETH_WITHDRAW_ABI=[
  'function withdraw(uint256)'
];

// ---------- balances & allowance ----------
async function getErc20Balance(provider, token, owner){
  try{ const c=new ethers.Contract(token, ERC20_ABI, provider); return await c.balanceOf(owner); }catch{ return 0n; }
}

async function ensureAllowance({provider, wallet, token, owner, spender, wantAmount, log=noopLog}){
  const c = new ethers.Contract(token, ERC20_ABI, provider);
  let dec=18; try { dec = await c.decimals(); } catch {}
  try {
    const [bal, cur] = await Promise.all([ c.balanceOf(owner), c.allowance(owner, spender) ]);
    log.dbg(`[preflight] tokenIn=${token} | balance=${bal} | allowance(${spender})=${cur} | need≈${wantAmount}`);
    if(cur >= wantAmount){ log.dbg(`[approve] allowance OK (>= need)`); return; }
  } catch {}
  const cW = c.connect(wallet);
  try{
    const tx1 = await cW.approve(spender, 0);
    log.dbg(`[approve] reset→0: ${tx1.hash}`);
    await tx1.wait(1);
  }catch(e){ log.dbg(`[approve] reset→0 skipped: ${e?.shortMessage||e?.message||e}`); }
  const tx2 = await cW.approve(spender, ethers.MaxUint256);
  log.dbg(`[approve] set→MAX: ${tx2.hash}`);
  await tx2.wait(1);
  const after = await c.allowance(owner, spender);
  log.dbg(`[approve] post-allowance=${after}`);
}

async function checkBalanceAndApprove({provider, signer, owner, token, spender, needAmount, log}) {
  const bal = await getErc20Balance(provider, token, owner);
  if (bal === 0n) { log.dbg(`[check] saldo ${token} = 0`); }
  const need = needAmount && needAmount>0n ? needAmount : (ethers.MaxUint256/4n);
  await ensureAllowance({provider, wallet: signer, token, owner, spender, wantAmount: need, log});
  return bal;
}

// ---------- fee & gas ----------
async function buildGasOverrides(provider, add=0){
  const fee=await provider.getFeeData();
  const bump=v=>v?(v+v*BigInt(Math.floor(add))/100n):v;
  if(fee.maxFeePerGas && fee.maxPriorityFeePerGas) return {type:2,maxFeePerGas:bump(fee.maxFeePerGas),maxPriorityFeePerGas:bump(fee.maxPriorityFeePerGas)};
  return {type:0, gasPrice:bump(fee.gasPrice ?? 1_000_000_000n)};
}

// ---------- wrap (support "max") ----------
async function doWrapIfNeeded({ provider, wallet, owner, SW, log=noopLog, minNativeForFeeBN=0n, wrapRetry }) {
  if (!truthy(SW.wrapFirst)) return { attempted:false, ok:true };
  const wtoken = SW.wtoken;
  if (!isAddr(wtoken)) { log.dbg('[wrap] skip: wtoken invalid'); return { attempted:false, ok:true }; }

  let value = 0n;
  if (String(SW.value).toLowerCase()==='max'){
    const native = await provider.getBalance(owner);
    const keep = minNativeForFeeBN>0n ? minNativeForFeeBN : 0n;
    if (native <= keep){ log.mini(`wrap skip (native<=minFee)`); return { attempted:false, ok:true }; }
    value = native - keep;
  } else {
    try { value = BigInt(SW.value || '0'); } catch { value = 0n; }
  }
  if (value <= 0n) { log.dbg('[wrap] skip: value=0'); return { attempted:false, ok:true }; }

  const tryWrap = async () => {
    const w = new ethers.Contract(wtoken, WETH_LIKE_ABI, provider).connect(wallet);
    try {
      const tx = await w.deposit({ value });
      const rc = await tx.wait(1);
      log.mini(`wrap success tx ${shortHash(tx.hash)}`);
      return true;
    } catch (e) { log.dbg(`[wrap] helper deposit() failed: ${e?.shortMessage||e?.message||String(e)}`); }
    try {
      const gasLimit = Number(SW.wrapGasLimit || 120000);
      const tx = await wallet.sendTransaction({ to: wtoken, data: '0xd0e30db0', value, gasLimit });
      await tx.wait(1);
      log.mini(`wrap success tx ${shortHash(tx.hash)}`);
      return true;
    } catch (e2) { throw new Error(e2?.shortMessage||e2?.message||String(e2)); }
  };

  const tries = wrapRetry?.attempts ?? 1;
  const delayMs = wrapRetry?.delayMs ?? 0;
  const backoff = wrapRetry?.backoff ?? 1.0;

  let d = Math.max(0, Number(delayMs)||0);
  const bf = Math.max(1, Number(backoff)||1);
  for (let i=1;i<=tries;i++){
    try{
      if (i>1){ log.essential(`[retry wrap] ${i}/${tries}`); await sleep(d); d=Math.floor(d*bf); }
      await tryWrap();
      return { attempted:true, ok:true };
    }catch(e){
      if (i===tries){ log.mini(`wrap error: ${e?.message || String(e)}`); return { attempted:true, ok:false, reason: String(e) }; }
    }
  }
  return { attempted:true, ok:false, reason:'wrap failed' };
}

// ---------- attempt loop ----------
async function attemptLoop({ name, tries, delayMs, backoff, jitterMs, onAttempt, log }){
  let d = Math.max(0, Number(delayMs)||0);
  const bf = Math.max(1, Number(backoff)||1);
  const jit = Math.max(0, Number(jitterMs)||0);
  for (let i=1; i<=tries; i++){
    try{
      if (i>1){
        log.essential(`[retry ${name}] ${i}/${tries}`);
        const jitter = jit ? Math.floor((Math.random()*2-1)*jit) : 0;
        const wait = Math.max(0, d + jitter);
        await sleep(wait);
        d = Math.floor(d*bf);
      }
      return await onAttempt(i);
    }catch(e){
      if (i===tries) throw e;
    }
  }
}

// ---------- single-route ----------
async function runOneRoute({ ctx, SWin, owner, signer, provider, globalFlags }){
  const log = ctx.log || noopLog;
  const DEBUG_ALL = ctx.DEBUG_ALL;

  const SW = { ...(SWin||{}) };

  const ROUTER = String(SW.router||'').trim();
  if(!isAddr(ROUTER)){ log.mini(`swap ${SW.name||'-'} error: invalid router`); return { ok:false, reason:'invalid router' }; }

  const STRICT_A_ONLY = !!(globalFlags?.STRICT_A_ONLY);
  const RESIM_BEFORE = !!(globalFlags?.RESIM_BEFORE);

  // retry settings
  const tries   = Number(SW?.retry?.attempts ?? ctx.config?.swap?.retry?.attempts ?? 3);
  const delayMs = Number(SW?.retry?.delayMs ?? ctx.config?.swap?.retry?.delayMs ?? 10_000);
  const backoff = Number(SW?.retry?.backoff ?? ctx.config?.swap?.retry?.backoff ?? 1.0);
  const jitterMs= Number(SW?.retry?.jitterMs ?? ctx.config?.swap?.retry?.jitterMs ?? 0);

  // rpc retry defaults
  const rpcRetry = {
    tries : Number(ctx.config?.swap?.rpcRetry?.tries ?? 6),
    base  : Number(ctx.config?.swap?.rpcRetry?.base ?? 600),
    backoff: Number(ctx.config?.swap?.rpcRetry?.backoff ?? 1.9),
    jitter : Number(ctx.config?.swap?.rpcRetry?.jitter ?? 250),
    pollMs : Number(ctx.config?.swap?.rpcRetry?.pollMs ?? 4000),
    totalMs: Number(ctx.config?.swap?.rpcRetry?.totalMs ?? 300_000),
  };

  // min native fee for wrap:max
  const minFeeStr = String(ctx?.config?.swap?.minNativeForFee || '0');
  let minNativeForFeeBN = 0n; try { minNativeForFeeBN = ethers.parseUnits(minFeeStr || '0', 18); } catch {}

  // 0) Optional wrap
  try { await doWrapIfNeeded({ provider, wallet: signer, owner, SW, log, minNativeForFeeBN, wrapRetry: { attempts: tries, delayMs, backoff } }); } catch {}

  // 1) Raw calldata
  const raw = String(SW.calldata||'').trim();
  if(!/^0x[0-9a-fA-F]{8,}$/.test(raw)){ log.mini(`swap ${SW.name||'-'} error: invalid calldata`); return { ok:false, reason:'invalid calldata' }; }
  let data = applyPatches({ dataHex: raw, patches: Array.isArray(SW.patches)?SW.patches:[], owner, log, debugAll: DEBUG_ALL });

  // 2) Multicall sub
  let sub = data;
  if (lc(strip0x(data).slice(0,8))==='ac9650d8'){
    const iface=new ethers.Interface(['function multicall(bytes[] data)']);
    const arr=iface.decodeFunctionData('multicall',data).data||[];
    if(!arr.length){ log.mini(`swap ${SW.name||'-'} error: empty multicall`); return { ok:false, reason:'empty multicall' }; }
    const ix = Number(SW?.dynamicFixes?.subIndex ?? 0);
    sub=with0x(strip0x(arr[ix] || arr[0]));
  }

  // 3) Selector check
  if (lc(strip0x(sub).slice(0,8))!=='1679c792'){
    log.dbg('[swap] not 0x1679c792 selector');
    return { ok:false, reason:'wrong selector' };
  }

  // 4) Parse direction
  const WANT_IN  = String(SW.tokenIn||'').trim();
  const WANT_OUT = String(SW.tokenOut||'').trim();
  if(!isAddr(WANT_IN)||!isAddr(WANT_OUT)){ log.mini(`swap ${SW.name||'-'} error: missing tokenIn/out`); return { ok:false, reason:'missing tokenIn/out' }; }

  let {A,B,slots} = parse1679(sub);

  let pick=null;
  if(lc(A.tokenIn)===lc(WANT_IN) && lc(A.tokenOut)===lc(WANT_OUT)) pick = { ...A, side:'A' };
  else if (!STRICT_A_ONLY && lc(B.tokenIn)===lc(WANT_IN) && lc(B.tokenOut)===lc(WANT_OUT)) pick = { ...B, side:'B' };

  if(!pick){
    const why = STRICT_A_ONLY ? 'strictAOnly' : 'direction mismatch';
    log.mini(`swap ${SW.name||'-'} error: ${why}`);
    return { ok:false, reason:'direction mismatch' };
  }

  // 5) Payer guard
  if(isAddr(pick.payer) && lc(pick.payer)!==lc(owner)){
    log.mini(`swap ${SW.name||'-'} error: payer mismatch`);
    return { ok:false, reason:'payer mismatch' };
  }

  // 6) amount:max — patch nilai amountIn ke saldo tokenIn
  if (String(SW.amount).toLowerCase()==='max'){
    const bal = await getErc20Balance(provider, pick.tokenIn, owner);
    const amtIdx = slots[0] ?? 5;
    sub = setWordAt(sub, amtIdx, bal);
    if (lc(strip0x(data).slice(0,8))==='ac9650d8'){
      const iface=new ethers.Interface(['function multicall(bytes[] data)']);
      const arr=iface.decodeFunctionData('multicall',data).data||[];
      const ix = Number(SW?.dynamicFixes?.subIndex ?? 0);
      arr[ix] = sub;
      data = iface.encodeFunctionData('multicall',[arr]);
    } else {
      data = sub;
    }
    try { pick.amountIn = bal; } catch {}
  }

  // 7) Pre allowance
  const needBefore = pick.amountIn && pick.amountIn>0n ? pick.amountIn : (ethers.MaxUint256/4n);
  await checkBalanceAndApprove({provider, signer, owner, token: pick.tokenIn, spender: ROUTER, needAmount: needBefore, log});

  // 8) Attempt loop
  const net=await provider.getNetwork();
  log.dbg(`\n[rpc] chainId=${Number(net.chainId)} | router=${ROUTER} | acct=${owner} | route=${SW.name||'-'}`);

  let txHash=null;

  await attemptLoop({
    name: `swap ${SW.name||'-'}`,
    tries: tries,
    delayMs, backoff, jitterMs,
    log,
    onAttempt: async (_idx)=>{

      // simulate (retry)
      try {
        await callWithRetry(provider, { from: owner, to: ROUTER, data, value: 0n }, {
          tries: rpcRetry.tries, base: rpcRetry.base, backoff: rpcRetry.backoff, jitter: rpcRetry.jitter, log
        });
      } catch (e) {
        await checkBalanceAndApprove({provider, signer, owner, token: pick.tokenIn, spender: ROUTER, needAmount: needBefore, log});
        throw e;
      }

      // estimateGas (retry) + headroom
      let gasLimit;
      try{
        const est = await estimateGasWithRetry(provider, { from: owner, to: ROUTER, data, value: 0n }, {
          tries: rpcRetry.tries, base: rpcRetry.base, backoff: rpcRetry.backoff, jitter: rpcRetry.jitter, log
        });
        const pct = BigInt(SW?.gas?.limitBumpPercent ?? ctx.config?.swap?.gas?.limitBumpPercent ?? 25);
        const add = BigInt(SW?.gas?.limitAdd         ?? ctx.config?.swap?.gas?.limitAdd         ?? 30000);
        const min = BigInt(SW?.gas?.minGasLimit      ?? ctx.config?.swap?.gas?.minGasLimit      ?? 0);
        let bumped = (BigInt(est) * (100n + pct)) / 100n + add;
        if (bumped < min) bumped = min;
        gasLimit = bumped;
        log.dbg(`[gas] est=${est} → bumped=${gasLimit} (pct=${pct}%, +${add})`);
      }catch(e){
        await checkBalanceAndApprove({provider, signer, owner, token: pick.tokenIn, spender: ROUTER, needAmount: needBefore, log});
        throw e;
      }

      // resimulate before send
      if (RESIM_BEFORE) {
        try {
          await callWithRetry(provider, { from: owner, to: ROUTER, data, value: 0n }, {
            tries: rpcRetry.tries, base: rpcRetry.base, backoff: rpcRetry.backoff, jitter: rpcRetry.jitter, log
          });
        } catch (e) {
          await checkBalanceAndApprove({provider, signer, owner, token: pick.tokenIn, spender: ROUTER, needAmount: needBefore, log});
          throw e;
        }
      }

      // send
      let tx;
      try {
        const gasOv=await buildGasOverrides(provider, Number(SW?.gas?.addPercent??0));
        tx = await signer.sendTransaction({to:ROUTER,data,value:0n,gasLimit, ...gasOv});
      } catch (eSend) {
        await checkBalanceAndApprove({provider, signer, owner, token: pick.tokenIn, spender: ROUTER, needAmount: needBefore, log});
        throw eSend;
      }

      // wait receipt (retry polling; avoids -32064 Proxy error)
      if(SW?.waitForReceipt!==false){
        const rc = await waitForReceiptSafe(provider, tx.hash, {
          pollMs : rpcRetry.pollMs,
          totalMs: rpcRetry.totalMs,
          tries  : Math.max(4, rpcRetry.tries),
          base   : rpcRetry.base,
          backoff: rpcRetry.backoff,
          jitter : rpcRetry.jitter,
          log
        });
        if (!rc || String(rc.status) !== '0x1') {
          throw new Error('onchain revert');
        }
        txHash = tx.hash;
        log.mini(`swap ${SW.name||'-'} success tx ${shortHash(txHash)}`);
      } else {
        txHash = tx.hash;
        log.mini(`swap ${SW.name||'-'} sent tx ${shortHash(txHash)}`);
      }
      return true;
    }
  });

  return { ok:true, txHash };
}

// ---------- fee top-up helpers ----------
function pickWTokenFromCfg(cfg){
  // prioritas: route yang punya wtoken → balances.networks[0].erc20.address
  const rs = get(cfg,'swap.routes',[]);
  if (Array.isArray(rs)) {
    const rWith = rs.find(r => r && r.wtoken);
    if (rWith && isAddr(rWith.wtoken)) return rWith.wtoken;
  }
  const fromBalances = get(cfg,'balances.networks.0.erc20.address', null);
  return isAddr(fromBalances) ? fromBalances : null;
}
function pickBackRouteByName(cfg, name='ztusd/wankr'){
  const rs = get(cfg,'swap.routes',[]);
  if (!Array.isArray(rs)) return null;
  return rs.find(x => String(x?.name||'').toLowerCase() === String(name).toLowerCase()) || null;
}
function pickZtusdFromCfg(cfg){
  // ambil tokenIn dari route ztusd/wankr
  const r = pickBackRouteByName(cfg,'ztusd/wankr');
  return r?.tokenIn && isAddr(r.tokenIn) ? r.tokenIn : null;
}

async function execBackRouteOnce({ ctx, route, provider, signer }){
  const log = ctx.log || noopLog;
  const rpcRetry = {
    tries : Number(ctx.config?.swap?.rpcRetry?.tries ?? 6),
    base  : Number(ctx.config?.swap?.rpcRetry?.base ?? 600),
    backoff: Number(ctx.config?.swap?.rpcRetry?.backoff ?? 1.9),
    jitter : Number(ctx.config?.swap?.rpcRetry?.jitter ?? 250),
    pollMs : Number(ctx.config?.swap?.rpcRetry?.pollMs ?? 4000),
    totalMs: Number(ctx.config?.swap?.rpcRetry?.totalMs ?? 300_000),
  };

  const to   = String(route.router);
  const data = String(route.calldata);
  const value= 0n;

  // Light simulate + estimate (now safe via encodeTxObjForRpc)
  await callWithRetry(provider, { from: await signer.getAddress(), to, data, value }, rpcRetry);

  const est = await estimateGasWithRetry(provider, { from: await signer.getAddress(), to, data, value }, rpcRetry);
  const pct = BigInt(route?.gas?.limitBumpPercent ?? ctx.config?.swap?.gas?.limitBumpPercent ?? 25);
  const add = BigInt(route?.gas?.limitAdd         ?? ctx.config?.swap?.gas?.limitAdd         ?? 30000);
  const min = BigInt(route?.gas?.minGasLimit      ?? ctx.config?.swap?.gas?.minGasLimit      ?? 0);
  let gasLimit = (BigInt(est) * (100n + pct)) / 100n + add;
  if (gasLimit < min) gasLimit = min;
  log.dbg(`[gas][back] est=${est} → bumped=${gasLimit}`);

  const gasOv = await buildGasOverrides(provider, Number(route?.gas?.addPercent ?? 0));
  const tx = await signer.sendTransaction({ to, data, value, gasLimit, ...gasOv });
  const rc = await waitForReceiptSafe(provider, tx.hash, rpcRetry);
  if (!rc || String(rc.status) !== '0x1') throw new Error('back route revert');
  log.mini(`[feeTopup] execRouteOnce ${route.name} ✅ tx=${shortHash(tx.hash)}`);
  return rc;
}

async function unwrapWToken({ provider, signer, wtoken, amountWei, log=noopLog }){
  const c = new ethers.Contract(wtoken, WETH_WITHDRAW_ABI, provider).connect(signer);
  const tx = await c.withdraw(amountWei);
  const rc = await tx.wait(1);
  log.mini(`[feeTopup] unwrap WANKR → ANKR: ${ethers.formatUnits(amountWei,18)} (tx ${shortHash(tx.hash)})`);
  return rc;
}

// ---------- Fee Top-Up (SKIP if truly no balances) ----------
async function ensureNativeFee(ctx, { provider, signer }){
  try{
    const { address: owner, config, log=noopLog } = ctx;

    const feeCfg   = get(config,'swap.feeTopup', {});
    const enabled  = feeCfg?.enabled !== false;                   // default ON
    const minNStr  = String(feeCfg?.minNative ?? '0.02');
    const bufStr   = String(feeCfg?.buffer    ?? '0.005');
    const maxTries = Number(feeCfg?.maxTries ?? 2);
    const backName = String(feeCfg?.preferRouteBack || 'ztusd/wankr');

    if (!enabled) return;

    const minN  = ethers.parseUnits(minNStr, 18);
    const buf   = ethers.parseUnits(bufStr, 18);

    let nativeBal = await provider.getBalance(owner);
    if (nativeBal >= minN) return; // cukup

    const wtoken = pickWTokenFromCfg(config);
    const ztusd  = pickZtusdFromCfg(config);

    const wbal = wtoken ? await getErc20Balance(provider, wtoken, owner) : 0n;
    const zbal = ztusd  ? await getErc20Balance(provider, ztusd,  owner) : 0n;

    // Semua benar-benar nol → SKIP (jangan stop modul)
    if (nativeBal===0n && wbal===0n && zbal===0n){
      log.mini('[feeTopup] skip (no balances: ANKR=0, WANKR=0, ztUSD=0)');
      return;
    }

    const target = minN + buf;
    let need = target > nativeBal ? (target - nativeBal) : 0n;
    if (need === 0n) return;

    // 1) Prioritas: unwrap WANKR secukupnya
    if (wtoken && wbal>0n){
      const pull = need > wbal ? wbal : need;
      if (pull > 0n){
        try{
          await unwrapWToken({ provider, signer, wtoken, amountWei: pull, log });
          nativeBal = await provider.getBalance(owner);
          if (nativeBal >= minN) { log.mini('[feeTopup] OK (from WANKR unwrap)'); return; }
          need = target > nativeBal ? (target - nativeBal) : 0n;
        }catch(e){ log.mini(`[feeTopup] unwrap fail: ${e?.shortMessage||e?.message||String(e)}`); }
      }
    }

    // 2) Back route: ztusd/wankr → unwrap
    const backRoute = pickBackRouteByName(config, backName);
    if (!backRoute){
      log.mini(`[feeTopup] skip (back route "${backName}" not found)`);
      return;
    }
    if (!ztusd || zbal===0n){
      log.mini('[feeTopup] skip (no ztUSD to convert)');
      return;
    }
    if (!wtoken){ log.mini('[feeTopup] skip (no WANKR address to unwrap)'); return; }

    for (let i=1; i<=maxTries; i++){
      try{
        log.mini(`[feeTopup] try ${i}/${maxTries}: swap ${backName} → unwrap`);
        await execBackRouteOnce({ ctx, route: backRoute, provider, signer });

        const w2 = await getErc20Balance(provider, wtoken, owner);
        if (w2 > 0n){
          const pull = w2 > need ? need : w2;
          if (pull > 0n){
            await unwrapWToken({ provider, signer, wtoken, amountWei: pull, log });
            nativeBal = await provider.getBalance(owner);
            if (nativeBal >= minN){ log.mini('[feeTopup] OK (from back route)'); return; }
            need = target > nativeBal ? (target - nativeBal) : 0n;
          }
        }
      }catch(e){ log.mini(`[feeTopup] back route fail: ${e?.shortMessage||e?.message||String(e)}`); }
    }

    log.mini('[feeTopup] done (insufficient after tries, skipped further)');
  }catch(err){
    try{ ctx?.log?.warn?.('[feeTopup] error '+(err?.shortMessage||err?.message||String(err))); }catch{}
  }
}

// ---------- main (with autoback schedule, no early exit) ----------
export async function run(ctx){
  const level = String(ctx?.config?.log?.level || process.env.LOG_LEVEL || 'silent').toLowerCase();
  const DEBUG_ALL = level==='debugall';
  const DEBUG_API = DEBUG_ALL || level==='debugapi';

  const baseMini = ctx?.log?.mini || ((...a)=>console.log(...a));
  const log = {
    mini: (...a)=>baseMini(...a),
    essential: (...a)=>baseMini(...a),
    dbg: (...a)=>{ if (DEBUG_API) baseMini(...a); },
    insp: (...a)=>{ if (DEBUG_ALL) baseMini(...a); },
    mode: level
  };

  const { address: owner, wallet, env={}, config={} } = ctx;
  const RPC = env.NEURA_RPC || env.RPC_URL || 'https://testnet.rpc.neuraprotocol.io';
  const provider = new ethers.JsonRpcProvider(RPC);
  const signer = wallet.connect(provider);

  // Top-up GAS lebih dulu supaya route pertama pasti cukup fee
  try { await ensureNativeFee(ctx, { provider, signer }); } catch {}

  const SW = config.swap || {};
  const STRICT_A_ONLY = !!SW.strictAOnly;

  // routes normalize (times default 1)
  let routes = [];
  if (Array.isArray(SW.routes) && SW.routes.length) {
    routes = SW.routes.map(r => ({ ...(r||{}), name: r?.name || '-', times: Math.max(1, Number(r?.times ?? 1)) }));
  } else {
    routes = [{ ...SW, name: SW.name || '-', times: Math.max(1, Number(SW?.times ?? 1)) }];
  }

  // select by useRouter
  const rawUse = String(SW.useRouter||'').trim();
  let orderNames = [];
  if (!rawUse || rawUse.toLowerCase()==='both' || rawUse.toLowerCase()==='all') {
    orderNames = routes.map(r => r.name);
  } else {
    orderNames = rawUse.split(',').map(s => s.trim()).filter(Boolean);
  }
  const selected = orderNames.map(nm => routes.find(x => String(x.name)===nm)).filter(Boolean);

  // autoback schedule
  const doAutoback = truthy(SW.autoback);
  let execQueue = [];
  if (doAutoback && selected.length >= 2) {
    const pool = selected.map(r => ({ ...r, left: r.times }));
    const defaultCycles = pool.reduce((m,r)=> Math.min(m, r.left), Infinity);
    const cycles = Math.max(1, Number(SW.autobackCycles ?? defaultCycles));
    for (let c = 1; c <= cycles; c++) {
      for (let i = 0; i < pool.length; i++) {
        if (pool[i].left > 0) {
          execQueue.push({ ...pool[i], _cycle: c, _seq: i+1 });
          pool[i].left--;
        }
      }
    }
  } else {
    for (const r of selected) for (let i=1; i<=r.times; i++) execQueue.push({ ...r, _cycle: i, _seq: 1 });
  }

  log.dbg(`[multi] useRouter="${rawUse||'all'}" → ${execQueue.map(r=>r.name).join(', ')}`);

  let anySuccess = false;
  for (const r of execQueue) {
    const tag = (r.times>1 || doAutoback) ? `${r.name}` : r.name;
    try {
      // Jaga-jaga: setelah route sebelumnya, saldo native bisa turun — isi ulang dulu kalau di bawah ambang
      try { await ensureNativeFee(ctx, { provider, signer }); } catch {}

      const res = await runOneRoute({
        ctx: { ...ctx, log, DEBUG_ALL, config },
        SWin: r, owner, signer, provider,
        globalFlags: {
          STRICT_A_ONLY,
          RESIM_BEFORE: !!r.resimulateBeforeSend || !!(config.swap?.resimulateBeforeSend),
        }
      });
      if (res.ok) {
        anySuccess = true;
      } else {
        log.mini(`swap ${tag} error: ${res.reason}`);
      }
    } catch (e) {
      const msg = e?.shortMessage || e?.reason || e?.message || String(e);
      log.mini(`swap ${tag} error: ${msg}`);
    }
  }
  if (!anySuccess) log.mini(`swap all error`);

  // Final guard (opsional): setelah semua selesai, top-up lagi jika masih kurang
  await ensureNativeFee(ctx, { provider, signer });
}

export default { run };

// ---------- CLI runner ----------
if (import.meta.url === `file://${process.argv[1]}`) {
  (async () => {
    const OWNER_PK = process.env.OWNER_PK || process.env.PRIVATE_KEY;
    if (!OWNER_PK) { console.error('Env OWNER_PK/PRIVATE_KEY kosong.'); process.exit(1); }
    const wallet = new ethers.Wallet(OWNER_PK);
    const owner = await wallet.getAddress();

    const level = (process.env.LOG_LEVEL || 'silent').toLowerCase();
    const log = {
      mini: (...a)=>console.log(...a),
      essential: (...a)=>console.log(...a),
      dbg: (...a)=>{ if (level==='debugapi' || level==='debugall') console.log(...a); },
      insp: (...a)=>{ if (level==='debugall') console.log(...a); },
      mode: level
    };

    const config = {
      log: { level },
      swap: {
        useRouter: process.env.USE_ROUTER || 'both',
        strictAOnly: String(process.env.STRICT_A_ONLY||'true')==='true',
        disallowForceSend: String(process.env.DISALLOW_FORCE_SEND||'true')!=='false',
        resimulateBeforeSend: String(process.env.RESIM_BEFORE||'true')==='true',
        minNativeForFee: process.env.MIN_NATIVE_FOR_FEE || '0.1',
        autoback: truthy(process.env.AUTOBACK || 'false'),
        autobackCycles: process.env.AUTOBACK_CYCLES ? Number(process.env.AUTOBACK_CYCLES) : undefined,

        retry: {
          attempts: Number(process.env.RETRY_ATTEMPTS||3),
          delayMs:  Number(process.env.RETRY_DELAY_MS||10000),
          backoff:  Number(process.env.RETRY_BACKOFF||1.0),
          jitterMs: Number(process.env.RETRY_JITTER_MS||0),
        },

        // RPC polling + call/estimate retry knobs
        rpcRetry: {
          tries:   Number(process.env.RPC_TRIES||6),
          base:    Number(process.env.RPC_BASE_MS||600),
          backoff: Number(process.env.RPC_BACKOFF||1.9),
          jitter:  Number(process.env.RPC_JITTER_MS||250),
          pollMs:  Number(process.env.RPC_POLL_MS||4000),
          totalMs: Number(process.env.RPC_TOTAL_MS||300000),
        },

        wrapGasLimit: Number(process.env.WRAP_GAS_LIMIT||120000),

        // Optional feeTopup config via env (fallback defaults jika tidak ada)
        feeTopup: {
          enabled: String(process.env.FEE_TOPUP_ENABLED||'true')!=='false',
          minNative: process.env.FEE_TOPUP_MIN_NATIVE || '0.02',
          buffer: process.env.FEE_TOPUP_BUFFER || '0.005',
          maxTries: Number(process.env.FEE_TOPUP_MAX_TRIES||3),
          preferRouteBack: process.env.FEE_TOPUP_BACK_NAME || 'ztusd/wankr',
        },

        // global gas headroom default (bisa dioverride per route di YAML)
        gas: {
          limitBumpPercent: Number(process.env.GAS_LIMIT_BUMP_PCT||25),
          limitAdd: Number(process.env.GAS_LIMIT_ADD||30000),
          minGasLimit: Number(process.env.GAS_MIN_LIMIT||0)
        },

        routes: [
          // isi YAML kamu
        ]
      }
    };

    const ctx = { address: owner, wallet, env: process.env, config, log };
    await run(ctx);
  })().catch(e=>{ console.error(e); process.exit(1); });
}
