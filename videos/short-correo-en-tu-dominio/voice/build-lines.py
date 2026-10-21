# Arma voice/lines.json: tiempos de palabra de whisper large-v3 (cada clip) + el texto en pantalla.
# Sólo se corrige formato: la dirección dicha en partes se junta en un solo token con su ortografía real
# («hola arroba tu estudio punto MX» → «hola@tuestudio.mx»), «Mailmask» → «MailMask», «bandeja» → «Bandeja».
import json, subprocess

SCENES = ["hookA", "hookB", "plan1", "plan2", "plan3", "bandeja", "gratis", "cierre", "cta"]
FIX = {"Mailmask.": "MailMask.", "bandeja.": "Bandeja.", "mailmask.studio.": "mailmask.studio"}


def merge(words):
    out, i = [], 0
    while i < len(words):
        t = [w["text"] for w in words[i:i + 6]]
        low = [x.lower().strip(".,") for x in t]
        # «hola arroba tu estudio punto MX»
        if low[:6] == ["hola", "arroba", "tu", "estudio", "punto", "mx"]:
            out.append({"w": "hola@tuestudio.mx" + (t[5][2:] if len(t[5]) > 2 else ""), "s": words[i]["start"], "e": words[i + 5]["end"]}); i += 6; continue
        # «name servers» → «nameservers» (vocabulario correcto en pantalla)
        if low[:2] == ["name", "servers"]:
            out.append({"w": "nameservers" + t[1][7:], "s": words[i]["start"], "e": words[i + 1]["end"]}); i += 2; continue
        w = words[i]
        out.append({"w": FIX.get(w["text"], w["text"]), "s": w["start"], "e": w["end"]}); i += 1
    return out


out = []
for scene in SCENES:
    ws = json.load(open(f"voice/tr-{scene}/transcript.json"))
    dur = float(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", f"voice/{scene}.wav"], capture_output=True, text=True).stdout)
    words = merge(ws)
    # signos de la frase escrita (la voz los respeta, whisper no siempre)
    for w in words:
        if scene == "hookA" and w["w"] == "tuestudio.mx.": w["w"] = "tuestudio.mx,"
        if scene == "gratis" and w["w"] == "gratis": w["w"] = "gratis,"
        if scene == "plan3" and w["w"] == "y": w["w"] = "Y"
        if scene == "plan2" and w["w"] == "Mailmask": w["w"] = "MailMask,"
        if scene == "cierre" and w["w"] == "tuestudio.mx": w["w"] = "tuestudio.mx,"
    out.append({"scene": scene, "file": f"voice/{scene}.wav", "dur": round(dur, 3), "words": words})
json.dump(out, open("voice/lines.json", "w"), ensure_ascii=False, indent=1)
for l in out: print(l["scene"], l["dur"], " ".join(w["w"] for w in l["words"]))
