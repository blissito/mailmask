# Guion por beat — «Crea un correo nuevo en el dominio que ya tienes» (para aprobar)

Lienzo 1080×1920, ~34 s, voz em_santa (Kokoro). Tiempos estimados a 2.8 palabras/s; se ajustan con el TTS real.

## Molde (distinto de los shorts anteriores)

- `short-01-gmail-personal`: dos paneles por escena + persiana de columnas.
- `short-buzones`: columnas comparadas por altura + rebanadas sesgadas / máscara tipográfica.
- `comercial-2026-w42`: fachada con cortina metálica + celdas WebGPU.
- **Este:** **un solo objeto grande al centro, sobre un tapete de corte** (cuadrícula de diseñador, líneas
  finas sobre crema, se desliza 1 celda por escena y cierra sin salto). La cámara no corta entre paneles:
  **atraviesa un glifo** con un **zoom-punch**. Todo pasa en el escritorio del freelancer.

Énfasis por color y peso (la palabra se enciende en rojo `#d7263d` con un golpe de escala); **nada de subrayados, círculos ni tachados de plumón** (bliss, 21-oct). Contorno de tinta 6 px, sombra dura `8px 8px 0`, sin gradientes.
Zona útil: textos entre `y 260` y `y 1380`; nada clave en `x 930–1080` entre `y 880–1400`.
Subtítulos karaoke en `y 1250–1340` (una línea, 72 px), arriba de la franja que tapa TikTok.

## Beats

| # | t | Lo que se ve (objeto concreto, SVG animado) | Voz literal |
|---|---|---|---|
| 0 | 0.0–5.6 | **Fotograma 0 completo:** tarjeta de presentación gigante (−4°) «Estudio Ríos · diseño gráfico», renglones `www  tuestudio.mx` y `✉  estudio.rios.2011@gmail.com`. Detrás asoma una **hoja de cotización** («Cotización · $18,500», `De: estudio.rios.2011@gmail.com`). `gmail.com` se enciende en rojo en la tarjeta (0.6 s) y en la hoja (3.0 s); un sello «¿ES REAL?» cae sobre la cotización a 4.4 s. | «Tu tarjeta dice tuestudio punto mx, pero tus cotizaciones salen desde gmail punto com.» |
| C1 | 5.6–6.3 | **Cortinilla 1 · zoom-punch por la «@»**: la cámara se clava en la `@` del correo de la tarjeta; la `@` (roja, contorno de tinta) crece hasta que su trazo tapa las cuatro esquinas, sacudida de 2 cuadros, y el hueco de la «a» se abre con la escena siguiente adentro. | — |
| 2 | 6.3–13.0 | **Tablero de MailMask como objeto físico** (tarjeta crema con contorno): (1) un campo `tuestudio.mx` que se escribe tecla por tecla con un **teclado de 5 teclas** que baja con cada letra; (2) paso «Cambias tus nameservers»: etiquetas `NS → MailMask` y `Agente · asistente de IA`, y tres ilustraciones (fichero de tarjetas, buzón con sobres, navegador `promo.tuestudio.mx`); (3) sale un **gafete** `hola@tuestudio.mx` con un clip y se balancea. | «Escribes tu dominio en MailMask. Cambias tus nameservers a los de MailMask. Ahora el asistente de IA configura tus registros DNS por ti, da de alta tus correos nuevos y hasta publica tu landing page en un subdominio. Y creas hola arroba tuestudio punto mx.» |
| 3 | 13.0–18.9 | **Charola de escritorio rotulada «Bandeja»**: cae un sobre `cliente@empresa.com → hola@tuestudio.mx` (rebote); el sobre se abre, sale la hoja y encima se escribe la respuesta con la firma «Estudio Ríos · hola@tuestudio.mx»; la hoja se dobla en **avión de papel** y sale por la izquierda con estela punteada. | «Tu cliente escribe a hola arroba tuestudio punto mx, y tú respondes desde la Bandeja.» |
| 4 | 18.9–23.2 | **Llavero con cinco gafetes** (`hola@`, `ventas@`, `pagos@`, `citas@`, `ana@`) que caen uno por uno en el aro; arriba una etiqueta de precio de papel «$0» atada con hilo que se balancea. | «Recibir y responder es gratis, con hasta cinco direcciones en tu dominio.» |
| C2 | 23.2–23.8 | **Cortinilla 2 · zoom-punch por la máscara**: la calcomanía de la máscara entra girando, la cámara se clava en el **ojo** derecho; el rojo de la máscara tapa las cuatro esquinas y el ojo se abre sobre la tarjeta del cierre. | — |
| 5 | 23.8–34.0 | **La tarjeta del inicio, transformada**, misma posición y ángulo: el renglón de correo se reescribe a `hola@tuestudio.mx`; `tuestudio.mx` se enciende en rojo en los dos renglones; la calcomanía de la máscara se pega en la esquina con un golpe (sello). Abajo entra el CTA: botón rojo **«Crea tu correo gratis»**, `mailmask.studio/correo-en-tu-dominio`, «hoy, 21 de octubre». A 31.4 s un **pósit rosa** se pega sobre el renglón `www`: «Lo siguiente: tu página». | «Tu tarjeta y tu correo ya dicen tuestudio punto mx. Crea tu correo gratis hoy, veintiuno de octubre, en mailmask punto studio. Lo siguiente: tu página en tuestudio punto mx.» |

Revisión de copy: cada frase se entiende sola; sin «alias»; sin «la suya», «eso», «ahí». «Bandeja» con mayúscula (nombre del producto).
TTS: escribir «tuestudio punto eme equis», «mailmask punto estudio» si Kokoro pronuncia en inglés; escuchar antes de renderizar.

## SFX por animación (al 0.7, sin repetir el mismo dos veces seguidas)

| t | Animación | SFX | Nota |
|---|---|---|---|
| 0.6 | `gmail.com` se enciende en rojo (tarjeta) | blip | |
| 3.0 | `gmail.com` se enciende en rojo (cotización) | tic | |
| 4.4 | sello «¿ES REAL?» `back.out(2)` 0.45 s | golpe de sello | impacto a 1/3 del tween → 4.55 s |
| 5.6 | zoom-punch a la `@` (0.5 s) | riser corto → whoosh | riser mientras se clava |
| 6.1 | `@` tapa la pantalla, sacudida | golpe grave (boom) | |
| 6.6–8.2 | teclas que bajan (12 letras) | tecleo mecánico, una tecla por letra | |
| 8.8 / 9.2 / 9.6 | tres etiquetas con cinta | cinta adhesiva ×3 (alternar 2 tomas) | |
| 10.0 / 10.3 / 10.6 | palomitas verdes | tic ascendente ×3 | |
| 11.6 | gafete `back.out(1.7)` + balanceo | pop + tintineo de clip | impacto a 0.37 del tween |
| 13.2 | sobre cae en la charola | caída de papel + rebote metálico | |
| 14.3 | sobre se abre | rasgón de papel | |
| 15.0–16.6 | respuesta que se escribe | lápiz sobre papel, bajo | |
| 17.4 | avión de papel sale | whoosh ligero | distinto del de C1 |
| 19.2–20.8 | cinco gafetes al aro | tintineos escalonados (5 notas subiendo) | |
| 21.4 | etiqueta «$0» se balancea | crujido de papel | |
| 23.2 | máscara entra girando y la cámara se clava | swish giratorio → riser | |
| 23.6 | rojo tapa la pantalla | glitch-crac | otra textura que el boom de C1 |
| 24.4 | el correo viejo sube y se va; el nuevo se escribe | whoosh corto | |
| 26.0 | `tuestudio.mx` en rojo en los dos renglones | tic + blip | |
| 27.0 | calcomanía `back.out(2)` | sello (otra toma que la de 4.4) | |
| 28.0 | botón CTA entra | pop grande | |
| 31.4 | pósit se pega | palmada de papel | |

## Cortinilla propuesta: zoom-punch por el glifo

No es persiana, ni rebanadas, ni celdas: la cámara **entra por un glifo que ya está en la escena** (la `@` de
la dirección, luego el ojo de la máscara). Del lenguaje de la piel: la dirección y la máscara son la marca.

- 0.0–0.35 s: escala 1 → 18 sobre el centro del glifo (`power3.in`), leve rotación −4° → 0°.
- 0.35–0.45 s: el trazo rojo cubre todo el lienzo; sacudida de 2 cuadros (±14 px). Verificar las cuatro esquinas en rojo.
- 0.45–0.70 s: el hueco interior se abre como máscara circular (`clip-path: circle()` de 0 a 1400 px, `back.out(1.4)`)
  con la escena siguiente ya completa adentro.
- Nunca un cuadro vacío: el rojo es sólido `#d7263d` con contorno de tinta; `blackdetect` sobre el entregado.

## Pendiente de decidir (bliss)

1. Fecha del CTA «hoy, 21 de octubre» (provisional).
2. ¿El teaser de la campaña 2 va en voz («Lo siguiente: tu página en tuestudio punto mx») o sólo en el pósit? En voz suma ~2.5 s (master 34 s).
3. Nombre del estudio de ejemplo: «Estudio Ríos» / `tuestudio.mx`.
4. Música: pista nueva de Openverse/Jamendo (BPM bajo con levantada al cierre, estilo «High hopes»), se elige midiendo.
5. Recorte de ~20 s para TikTok: beats 0 + 2 + 5.

## Aprobado y producido (21-oct-2026)
- CTA sin fecha (decisión de bliss): voz «Crea tu correo gratis en mailmask punto studio»; pantalla `mailmask.studio/correo-en-tu-dominio`.
- «Lo siguiente: tu página» sólo en el pósit. «Estudio Ríos» se queda.
- Música: «New Bed Sheets» de Helen Langfort (CC BY 3.0), crédito en `CREDITO-MUSICA.txt`; levantada (s 135.5 de la pista) en el CTA. «Way In» se descartó: crescendo de 35 dB, dejaba mudos los primeros 30 s.
- SFX: burbujas (3 tonos) y swings suaves sintetizados en `sfx.py` en lugar de pops, tics y golpes secos; el sello del cierre, la cinta y las cortinillas se quedan.
- Pipeline: `voice/lines.tsv` → TTS em_santa → `voice/build-lines.py` → `node score.mjs` → render → `python3 sfx.py` → `./mix.sh`.

## Ajustes de bliss (21-oct-2026, tarde)
- Audiencia: dueños de negocio chico y freelancers (30–50, celular). Nada técnico en voz, vocabulario correcto en pantalla.
- Máscara: la oficial del nav de `public/correo-en-tu-dominio.html`, sin repintar, sobre círculo crema con contorno de tinta (sello de la cortinilla 4 y calcomanía del cierre).

## Ajustes de bliss (21-oct-2026, noche)
- Fuera subrayados, círculos y tachados de plumón: el énfasis va con color y peso.
- El flujo que se recomienda es **delegar los nameservers** a MailMask, no pegar registros. Es el mensaje central: con el DNS en
  MailMask, el agente hace los cambios del dominio cuando se los pides. Datos verificados en `~/mailmask`:
  `create_dns_zone` crea la zona, copia los registros actuales y devuelve los nameservers (sus nombres cambian por dominio, por
  eso no salen en pantalla); el cambio tarda de 1 a 48 h (`dns_delegation_status`); el agente apunta el dominio a Vercel,
  Netlify, GitHub Pages, Cloudflare Pages, Render o Fly (`point_domain_to`), publica el sitio de EasyBits
  (`publish_easybits_site`) y edita registros (`set_dns_record`); los registros de correo están protegidos (`mcp.ts`).
- Voz plan2 (TTS, `npx hyperframes@0.8.145 tts -v em_santa -l es -s 1.1`): «Cambias tus neim sérvers a los de Méil Mask. Ahora el
  asistente de i a configura tus registros de ene ese por ti, da de alta tus correos nuevos y hasta publica tu lánding peich en
  un subdominio.» Pantalla: «Cambias tus nameservers», etiquetas «NS → MailMask» y «Agente · asistente de IA», y tres
  ilustraciones que entran cuando la voz las nombra: fichero de tarjetas («Registros DNS», `set_dns_record`), buzón que suelta
  sobres con @ («Correos nuevos», `create_alias`) y navegador `promo.tuestudio.mx` que se arma («Landing en tu subdominio»,
  `publish_easybits_site`). Ojo: EasyBits publica en `<slug del sitio>.tudominio`, por eso la voz no dice «el subdominio que tú
  quieras». Master: 44.3 s.
- Aprobados los tres renglones nuevos (21-oct-2026): voz del cierre «…tuestudio punto eme equis, y un agente administra tu dominio.»; la calcomanía de la máscara se pega cuando la voz dice «agente». Master: 46.1 s.
