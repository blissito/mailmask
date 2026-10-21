#!/usr/bin/env python3
"""Pista de efectos: lee score.gen.json y coloca cada efecto en su tiempo, con su ganancia (0.7 por defecto).
Los del catálogo CC0 (fixter2025/docs/shorts-taller/sfx) se leen del disco; los que no existen ahí
(plumón, lápiz, tecla, cinta, tintineo, palmada de pósit, glitch, burbujas, swing) se sintetizan aquí, con la duración
del movimiento que acompañan (campo `dur` de la partitura)."""
import json, os, subprocess, wave
import numpy as np

SR = 48000
HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.expanduser("~/fixter2025/docs/shorts-taller/sfx")
score = json.load(open(os.path.join(HERE, "score.gen.json")))
n = int(score["duration"] * SR)
out = np.zeros((n, 2))
rng = np.random.default_rng(7)
cache = {}


def env(length, attack=0.005, release=0.05):
    t = np.arange(length) / SR
    a = np.clip(t / attack, 0, 1)
    r = np.clip((length / SR - t) / release, 0, 1)
    return a * r


def bandpass(x, lo, hi):
    f = np.fft.rfft(x)
    fr = np.fft.rfftfreq(len(x), 1 / SR)
    f[(fr < lo) | (fr > hi)] = 0
    return np.fft.irfft(f, len(x))


def norm(x, peak=0.8):
    return x / (np.abs(x).max() + 1e-9) * peak


def synth(name, dur):
    L = int(dur * SR)
    t = np.arange(L) / SR
    if name in ("marker", "pencil"):
        # trazo: ruido filtrado con vaivén de la mano (≈7 Hz plumón, 11 Hz lápiz)
        lo, hi, rate = (1800, 6000, 7) if name == "marker" else (3000, 9000, 11)
        x = bandpass(rng.standard_normal(L), lo, hi) * (0.55 + 0.45 * np.abs(np.sin(np.pi * rate * t)))
        return norm(x * env(L, 0.02, 0.06), 0.55)
    if name in ("key", "key2"):
        L = int(0.06 * SR); t = np.arange(L) / SR
        f = 2400 if name == "key" else 2000
        x = bandpass(rng.standard_normal(L), f, f * 2.5) * np.exp(-t * 90) + 0.3 * np.sin(2 * np.pi * 180 * t) * np.exp(-t * 60)
        return norm(x, 0.7)
    if name in ("tape", "tape2"):
        L = int(0.28 * SR); t = np.arange(L) / SR
        sweep = 0.5 + 0.5 * np.sin(2 * np.pi * (30 if name == "tape" else 42) * t)
        x = bandpass(rng.standard_normal(L), 800, 5000) * sweep * env(L, 0.01, 0.08)
        return norm(x, 0.6)
    if name in ("jingle", "jingle2"):
        # llaves: parciales metálicos inarmónicos que decaen
        base = 2200 if name == "jingle" else 2650
        x = sum(np.sin(2 * np.pi * base * k * t + k) * np.exp(-t * (6 + 3 * k)) for k in (1, 1.47, 2.09, 2.76))
        x += sum(np.sin(2 * np.pi * base * 1.12 * k * t) * np.exp(-(t - 0.07).clip(0) * 9) * (t > 0.07) for k in (1, 1.53))
        return norm(x * env(L, 0.002, 0.08), 0.5)
    if name == "slap":
        L = int(0.18 * SR); t = np.arange(L) / SR
        x = bandpass(rng.standard_normal(L), 300, 4000) * np.exp(-t * 35) + 0.6 * np.sin(2 * np.pi * 120 * t) * np.exp(-t * 30)
        return norm(x, 0.75)
    if name == "glitch":
        L = int(0.32 * SR)
        x = np.zeros(L)
        for i in range(0, L, int(0.02 * SR)):
            seg = min(int(0.02 * SR), L - i)
            x[i:i + seg] = np.sign(np.sin(2 * np.pi * rng.choice([90, 140, 220, 330]) * np.arange(seg) / SR)) * rng.uniform(0.3, 1)
        return norm(bandpass(x, 60, 7000) * env(L, 0.002, 0.1), 0.6)
    if name in ("bubble", "bubble2", "bubble3"):
        # burbuja: seno con barrido exponencial hacia arriba y caída rápida (≈0.11 s)
        L = int(0.11 * SR); t = np.arange(L) / SR
        f0, f1 = {"bubble": (520, 1500), "bubble2": (680, 1900), "bubble3": (420, 1150)}[name]
        f = f0 * (f1 / f0) ** (t / t[-1])
        ph = 2 * np.pi * np.cumsum(f) / SR
        x = (np.sin(ph) + 0.18 * np.sin(2 * ph)) * np.exp(-t * 26) * np.clip(t / 0.003, 0, 1)
        return norm(x, 0.7)
    if name in ("swing", "swing2"):
        # swing suave: aire filtrado que sube y baja con el movimiento (dura lo que dura el tween)
        lo, hi = (350, 2600) if name == "swing" else (500, 3400)
        low, high = bandpass(rng.standard_normal(L), lo, lo * 3), bandpass(rng.standard_normal(L), hi / 3, hi)
        m = t / max(t[-1], 1e-6)
        x = (low * (1 - m) + high * m) * np.sin(np.pi * m) ** 2
        return norm(x, 0.45)
    raise KeyError(name)


def load(e):
    name, dur = e["file"], e.get("dur", 0.4)
    key = (name, dur)
    if key not in cache:
        path = os.path.join(LIB, name + ".wav")
        if os.path.exists(path):
            raw = subprocess.run(["ffmpeg", "-v", "error", "-i", path, "-f", "s16le", "-ac", "2", "-ar", str(SR), "-"], capture_output=True, check=True).stdout
            cache[key] = np.frombuffer(raw, np.int16).reshape(-1, 2).astype(float) / 32768
        else:
            mono = synth(name, dur)
            cache[key] = np.stack([mono, mono], axis=1)
    return cache[key]


for e in score["sfx"]:
    s = load(e); a = int(round(e["t"] * SR)); b = min(n, a + len(s))
    out[a:b] += s[: b - a] * e["gain"]
pk = np.abs(out).max()
print(f"{len(score['sfx'])} efectos · pico {20*np.log10(pk):.1f} dBFS")
with wave.open(os.path.join(HERE, "sfx.wav"), "wb") as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(SR)
    w.writeframes((np.clip(out, -1, 1) * 32767).astype(np.int16).tobytes())
