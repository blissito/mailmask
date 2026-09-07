// Mixes narration (from the render), ducked BGM and SFX; muxes onto the render without re-encoding video.
import { execSync } from "node:child_process";
import fs from "node:fs";
const T = JSON.parse(fs.readFileSync("sfx-times.json"));
const RENDER = process.argv[2] || "renders/v2.mp4", OUT = process.argv[3] || "renders/final.mp4";
const BGM = "bgm/electron-wake.wav", TOTAL = T.TOTAL;
const ms = (s) => Math.round(s * 1000);
const ev = []; // [file, at, gain]
for (const c of T.cuts) { ev.push(["riser", c - 0.635 - 1.05, 0.55]); ev.push(["thud", c - 0.05, 0.9]); }
for (const s of T.swaps) ev.push(["whoosh", s, 0.5]);
for (const p of [...new Set(T.pulses)]) ev.push(["click", p, 0.45]);
ev.sort((a, b) => a[1] - b[1]);
const inputs = ["-i", RENDER, "-i", BGM, ...ev.flatMap(([n]) => ["-i", `sfx/${n}.wav`])];
const chains = [];
chains.push(`[0:a]loudnorm=I=-15:TP=-1.5:LRA=11,aresample=48000,apad=whole_dur=${TOTAL},asplit=2[va][vb]`);
chains.push(`[1:a]atrim=0:${TOTAL},loudnorm=I=-26:TP=-3:LRA=11,afade=t=in:d=1.2,afade=t=out:st=${(TOTAL - 2.5).toFixed(2)}:d=2.5,apad=whole_dur=${TOTAL}[bg]`);
chains.push(`[bg][va]sidechaincompress=threshold=0.02:ratio=8:attack=8:release=500[bd]`);
ev.forEach(([n, at, g], i) => chains.push(`[${i + 2}:a]volume=${g},aresample=48000,adelay=${ms(at)}:all=1,apad=whole_dur=${TOTAL}[e${i}]`));
const all = ["[vb]", "[bd]", ...ev.map((_, i) => `[e${i}]`)].join("");
chains.push(`${all}amix=inputs=${ev.length + 2}:normalize=0:duration=first,atrim=0:${TOTAL}[pre]`);
fs.writeFileSync("mix.txt", chains.join(";\n"));
execSync(`ffmpeg -v error -y ${inputs.map((x) => `"${x}"`).join(" ")} -filter_complex_script mix.txt -map "[pre]" -ar 48000 /tmp/premix.wav`, { stdio: "inherit" });
const L = execSync(`ffmpeg -i /tmp/premix.wav -af ebur128=peak=true -f null - 2>&1 | grep -E "^\\s+I:" | tail -1 | awk '{print $2}'`).toString().trim();
const G = (-15.7 - parseFloat(L)).toFixed(2);
execSync(`ffmpeg -v error -y -i /tmp/premix.wav -af "volume=${G}dB,alimiter=limit=0.84" /tmp/mix.wav`, { stdio: "inherit" });
execSync(`ffmpeg -v error -y -i "${RENDER}" -i /tmp/mix.wav -map 0:v -map 1:a -c:v copy -c:a aac -b:a 192k -movflags +faststart -t ${TOTAL} "${OUT}"`, { stdio: "inherit" });
console.log(ev.length, "eventos · LUFS premix", L, "· ganancia", G, "dB →", OUT);
console.log("LUFS final:", execSync(`ffmpeg -i "${OUT}" -af ebur128 -f null - 2>&1 | grep -E "^\\s+I:" | tail -1 | awk '{print $2}'`).toString().trim());
console.log("negros:", execSync(`ffmpeg -i "${OUT}" -vf blackdetect=d=0.05:pic_th=0.98 -an -f null - 2>&1 | grep -c black_start || true`).toString().trim());
console.log(execSync(`ffprobe -v error -select_streams v -show_entries stream=start_time,width,height,duration -of csv=p=0 "${OUT}"`).toString().trim());
