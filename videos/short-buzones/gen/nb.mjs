// Genera escenas con Nano Banana 2 (gemini-3.1-flash-image) usando al luchador del 404 como referencia.
// Uso: node nb.mjs <salida.png> "<prompt>"
import { readFileSync, writeFileSync } from "node:fs";
const env = readFileSync(`${process.env.HOME}/ghosty-studio/.env`, "utf8");
const key = env.match(/^GOOGLE_GENERATIVE_AI_API_KEY="?([^"\n]+)/m)[1];
const ref = readFileSync(`${process.env.HOME}/mailmask/public/img/404-il.jpg`).toString("base64");
const [out, scene] = process.argv.slice(2);
const style = `Use the attached image as the character and style reference: the SAME masked luchador (red mask with white and black design, black singlet strap, red trunks, black boots with red laces), same flat editorial ink illustration style: thick black outlines, solid flat fills, palette limited to cream background #faf6ee, black ink, mask red #d7263d, a touch of gold #f2b705. Personality like a classic Mexican cinema hero (El Santo): strong, muscular, noble and calm, friendly and approachable, kind eyes, a warm confident smile visible through the mask's mouth opening, never goofy, never angry. Keep OUR red mask design from the reference, not a silver mask. No gradients, no blur, no glow, no grain, no photorealism. Absolutely no text, letters, numbers or logos anywhere. Vertical 9:16 composition.`;
const body = { contents: [{ parts: [{ inlineData: { mimeType: "image/jpeg", data: ref } }, { text: `${style}\n\nScene: ${scene}` }] }],
  generationConfig: { responseModalities: ["IMAGE"], imageConfig: { aspectRatio: "9:16", imageSize: "2K" } } };
const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-image:generateContent?key=${key}`,
  { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
const j = await r.json();
const img = j.candidates?.[0]?.content?.parts?.find((p) => p.inlineData)?.inlineData;
if (!img) { console.error(JSON.stringify(j).slice(0, 800)); process.exit(1); }
writeFileSync(out, Buffer.from(img.data, "base64"));
console.log("ok", out);
