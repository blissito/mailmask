// Word timings measured with large-v3 on assets/voice/em_santa/s*.wav (relative to each clip)
import fs from "node:fs";
export const BREATH = 0.9;
export const voice = [0, 1, 2, 3, 4].map((i) => JSON.parse(fs.readFileSync(new URL(`./.tts/align/s${i}.json`, import.meta.url))));
export const dur = [3.669, 3.563, 2.859, 4.331, 5.525];
// Scene = breath + voice + tail (longer tails: the cut breathes before the wipe)
const tail = [1.1, 1.2, 1.1, 1.3, 3.0];
export const start = [];
let t = 0;
for (let i = 0; i < 5; i++) { start.push(t); t += BREATH + dur[i] + tail[i]; }
export const TOTAL = Math.round(t * 100) / 100;
export const at = (i, wordIdx) => start[i] + BREATH + voice[i][wordIdx].start;
export const CUTS = start.slice(1);
