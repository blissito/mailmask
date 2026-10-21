// Revisa los style frames con Chrome headless: zonas TikTok, texto tapado/recortado y separación
// mínima entre objetos [data-obj]. Uso: node verif/check-layout.mjs [frames.html] [sf1 sf2 ...]
// Sale con código 1 si algún cuadro falla.
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const CHROME = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const file = resolve(process.argv[2] || new URL('../styleframes/frames.html', import.meta.url).pathname);
let frames = process.argv.slice(3);
if (!frames.length) {
  const html = (await import('node:fs')).readFileSync(file, 'utf8');
  frames = [...html.matchAll(/<section class="f" id="([^"]+)"/g)].map(m => m[1]);
}

let failed = false;
for (const id of frames) {
  const dom = execFileSync(CHROME, ['--headless=new', '--disable-gpu', '--hide-scrollbars', '--window-size=1080,1920',
    '--virtual-time-budget=5000', '--dump-dom', `file://${file}#${id}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  const m = dom.match(/<pre id="zonecheck"[^>]*>([\s\S]*?)<\/pre>/);
  if (!m) { console.log(`✗ ${id}: no salió el resultado (#zonecheck)`); failed = true; continue; }
  const r = JSON.parse(m[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&'));
  const probs = ['inUnsafeZone', 'offCanvas', 'hidden', 'tooClose'].filter(k => r[k]?.length);
  if (probs.length) { failed = true; console.log(`✗ ${id}`); for (const k of probs) console.log(`   ${k}: ${r[k].join(' | ')}`); }
  else console.log(`✓ ${id}`);
}
process.exit(failed ? 1 : 0);
