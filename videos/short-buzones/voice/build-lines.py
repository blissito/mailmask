# Arma voice/lines.json: tiempos de palabra de whisper large-v3 (cada clip) + el texto en pantalla.
# Sólo se corrigen errores de oído y formato: «Mailmask» → «MailMask», «quiera» → «quieras», signos de la frase.
import json, subprocess
FIX = {"Correo": "¿Correo", "negocio.": "negocio?", "veces": "veces:", "975": "975", "99": "99", "5": "cinco", "persona": "persona:", "Mailmask": "MailMask",
       "quiera": "quieras", "ilimitados": "ilimitados:", "precio.": "precio:", "Mailmask.studio.": "mailmask.studio"}
out = []
for scene in ["hookA", "hookB", "buzon", "ilim", "cierreA", "cierreB", "cta"]:
    ws = json.load(open(f"voice/tr-{scene}/transcript.json"))
    dur = float(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", f"voice/{scene}.wav"], capture_output=True, text=True).stdout)
    out.append({"scene": scene, "file": f"voice/{scene}.wav", "dur": round(dur, 3),
                "words": [{"w": FIX.get(w["text"], w["text"]), "s": w["start"], "e": w["end"]} for w in ws]})
json.dump(out, open("voice/lines.json", "w"), ensure_ascii=False, indent=1)
for l in out: print(l["scene"], l["dur"], " ".join(w["w"] for w in l["words"]))
