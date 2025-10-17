// tui.mjs — grid TUI + session bar + right sidebar
import readline from 'node:readline';
const ESC = '\x1b[';
const hideCursor = ()=> process.stdout.write(ESC+'?25l');
const showCursor = ()=> process.stdout.write(ESC+'?25h');
const clr = ()=> process.stdout.write(ESC+'2J'+ESC+'H');

const repeat = (ch,n)=> new Array(Math.max(0,n)+1).join(ch);
const stripAnsi = s => String(s).replace(/\x1b\[[0-9;]*m/g,'');
const stripCtl  = s => String(s).replace(/[\u0000-\u001F\u007F]/g,'');

export function makeUI(CFG){
  const uiCfg = CFG?.ui || {};
  const enabled = uiCfg.enabled !== false;
  const panelCount = Math.max(1, Number(uiCfg.panels || 4));
  const maxLines = Math.max(30, Number(uiCfg.maxLinesPerPanel || 120));
  const TRUNC = Math.max(20, Number(uiCfg.truncateWidth || 90));
  const showSession = uiCfg.sessionBar !== false;
  const sessPct = Math.min(40, Math.max(10, Number(uiCfg.sessionHeightPct || 22)));
  const sidebarOn = uiCfg.sidebar !== false;
  const timestamp = !!uiCfg.timestamp;

  const termW = process.stdout.columns || 120;
  const termH = process.stdout.rows || 32;
  const sidebarW = sidebarOn ? Math.max(24, Math.min(36, Math.floor(termW*0.22))) : 0;
  const contentW = termW - sidebarW;

  const gridCols = Math.min(panelCount, 6);
  const gridRows = Math.ceil(panelCount / gridCols);
  const panelW = Math.floor(contentW / gridCols);
  const panelHTotal = showSession ? Math.floor(termH * (100 - sessPct)/100) : termH;
  const panelH = Math.max(6, Math.floor(panelHTotal / gridRows));
  const sessionH = showSession ? (termH - panelH*gridRows) : 0;

  const panels = new Array(panelCount).fill(0).map(()=>[]);
  const sessionLines = [];
  const sidebarLines = [];

  function drawBox(x,y,w,h,title){
    const top = '┌'+repeat('─',w-2)+'┐';
    const mid = '│'+repeat(' ',w-2)+'│';
    const bot = '└'+repeat('─',w-2)+'┘';
    process.stdout.write(`${ESC}${y};${x}H${top}`);
    for (let i=1;i<h-1;i++) process.stdout.write(`${ESC}${y+i};${x}H${mid}`);
    process.stdout.write(`${ESC}${y+h-1};${x}H${bot}`);
    if (title){
      const t = ' ' + title + ' ';
      process.stdout.write(`${ESC}${y};${x+2}H${t.slice(0, Math.max(0,w-4))}`);
    }
  }
  function writeLines(x,y,w,h,lines){
    const cap = h-2;
    const start = Math.max(0, lines.length - cap);
    const view = lines.slice(start).map(s=>{
      let flat = stripCtl(stripAnsi(String(s))).replace(/\r?\n|\r/g,' ');
      flat = flat.replace(/\s{2,}/g,' ').trim();
      if (flat.length>TRUNC) flat = flat.slice(0,TRUNC-1)+'…';
      return flat;
    });
    for (let i=0;i<cap;i++){
      const line = view[i] || '';
      process.stdout.write(`${ESC}${y+1+i};${x+1}H${line.padEnd(w-2,' ').slice(0,w-2)}`);
    }
  }
  function render(){
    if (!enabled) return;
    clr(); hideCursor();
    for (let p=0;p<panelCount;p++){
      const r = Math.floor(p / gridCols);
      const c = p % gridCols;
      const x = c*panelW + 1;
      const y = r*panelH + 1;
      drawBox(x,y,panelW,panelH, `Panel ${p+1}`);
      writeLines(x,y,panelW,panelH, panels[p]);
    }
    if (sidebarOn){
      const x = contentW + 1;
      const y = 1;
      drawBox(x,y,sidebarW, panelH*gridRows, 'SIDEBAR (Login/Re-Login)');
      writeLines(x,y,sidebarW, panelH*gridRows, sidebarLines);
    }
    if (showSession){
      const x = 1;
      const y = panelH*gridRows + 1;
      drawBox(x,y,termW,sessionH,'SESSION (Login/Expiry/Re-Login)');
      writeLines(x,y,termW,sessionH, sessionLines);
    }
  }

  function write(panelIndex, line, slotTag){
    if (!enabled) return;
    const idx = Math.max(0, Math.min(panelCount-1, panelIndex));
    const tag = slotTag ? `[${slotTag}] ` : '';
    const tm = timestamp ? new Date().toTimeString().slice(0,8)+' ' : '';
    panels[idx].push(tm+tag+line);
    if (panels[idx].length>maxLines) panels[idx].splice(0, panels[idx].length-maxLines);
    render();
  }
  function session(text){
    if (!enabled || !showSession) return;
    sessionLines.push(String(text));
    if (sessionLines.length>Math.max(100, maxLines)) sessionLines.splice(0, sessionLines.length-100);
    render();
  }
  function sessionSet(lines){
    if (!enabled || !showSession) return;
    sessionLines.length = 0;
    (lines||[]).forEach(l=> sessionLines.push(String(l)));
    render();
  }
  function sidebar(text){
    if (!enabled || !sidebarOn) return;
    sidebarLines.push(String(text));
    if (sidebarLines.length>Math.max(200, maxLines*2)) sidebarLines.splice(0, sidebarLines.length-200);
    render();
  }
  function sidebarSet(lines){
    if (!enabled || !sidebarOn) return;
    sidebarLines.length = 0;
    (lines||[]).forEach(l=> sidebarLines.push(String(l)));
    render();
  }

  let _nextPanel = 0;
  function assignAccount(i, addrShort){
    const panel = (_nextPanel++) % panelCount;
    const slot = `#${i+1}`;
    write(panel, `join [${slot}] ${addrShort}`, null);
    return { panel, slot };
  }

  const _initPromise = Promise.resolve().then(render);

  return { enabled, _initPromise, write, session, sessionSet, sidebar, sidebarSet, assignAccount };
}
