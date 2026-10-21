# Arma voice/lines.json: tiempos de palabra de whisper large-v3 (cada clip) + el texto en pantalla.
# Sólo se corrigen errores de oído y formato: «Verzel» → «Vercel», «Mailmask» → «MailMask», signos de la frase.
import json, subprocess
FIX = {
    ("webA", "Mailmask,"): "MailMask,", ("webA", "Web"): "web",
    ("webB", "Verzel,"): "Vercel,", ("webB", "EasyBits"): "EasyBits,", ("webB", "nada"): "nada,",
    ("apply", "aplicar"): "aplicar,", ("apply", "Mailmask"): "MailMask",
    ("cta", "Mailmask.studio."): "mailmask.studio",
}
out = []
for scene in ["hookA", "hookB", "webA", "webB", "apply", "cierre", "cta"]:
    ws = [{"w": w["text"], "s": w["start"], "e": w["end"]} for w in json.load(open(f"voice/tr-{scene}/transcript.json"))]
    fixed = []
    for w in ws:
        # el motor dice «das aplicar» con la a ligada; whisper la separa: se funde con «aplicar»
        if scene == "apply" and w["w"] == "a":
            continue
        fixed.append({**w, "w": FIX.get((scene, w["w"]), w["w"])})
    dur = float(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", f"voice/{scene}.wav"], capture_output=True, text=True).stdout)
    out.append({"scene": scene, "file": f"voice/{scene}.wav", "dur": round(dur, 3), "words": fixed})
json.dump(out, open("voice/lines.json", "w"), ensure_ascii=False, indent=1)
for l in out: print(l["scene"], l["dur"], " ".join(w["w"] for w in l["words"]))
