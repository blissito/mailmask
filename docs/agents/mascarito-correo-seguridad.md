# Mascarito IA contesta su correo: reglas de seguridad (22-oct-2026)

`mascarito@mailmask.studio` es un buzón público: cualquiera le escribe y lo que diga un correo puede intentar
darle órdenes al modelo. El código es `mascarito-mail.ts` + `mascarito-templates.ts`; las pruebas,
`mascarito-mail.test.ts`. Salió de dos investigaciones (inyección por correo y abuso de autorespondedores).

## Arquitectura
- **Action-selector** — el modelo sólo devuelve `{template, firstName}`; el servidor arma el correo. https://arxiv.org/abs/2506.08837
- **Cuarentena / dual-LLM** — el modelo es Mascarito, el mismo agente de Ghosty del panel (`GHOSTY_AGENT_ID`),
  pero este canal le manda `MAIL_INSTRUCTIONS` como `appendSystemPrompt` y un `turnToken` que no es un `mt_`: su MCP
  contesta 401, así que no puede leer ni tocar ninguna cuenta aunque lo engañen (se rompe la «trifecta letal»).
  https://simonwillison.net/2023/Apr/25/dual-llm-pattern/ · https://arxiv.org/abs/2503.18813 · https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- **Spotlighting** — el correo entra en texto plano, delimitado como dato no confiable y sin caracteres invisibles. https://arxiv.org/abs/2403.14720
- **Sin URLs ni texto del atacante** — EchoLeak (CVE-2025-32711) exfiltró por URLs; Gemini en Gmail cayó con texto oculto.
  Toda URL sale de una lista fija (sólo `www.mailmask.studio`), el único hueco es `firstName` (letras, ≤30) y se escapa.
  https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html · https://www.0din.ai/blog/phishing-for-gemini

## Puertas antes del modelo (`shouldAutoReply`)
- Sólo con `dmarcVerdict = PASS` (contra remitentes falsos y backscatter). https://docs.aws.amazon.com/ses/latest/dg/receiving-email-notifications-contents.html
- Nada si `Auto-Submitted` ≠ `no`, `Precedence: bulk|list|junk`, `List-Id`/`List-Unsubscribe`, Return-Path vacío,
  `noreply`/`mailer-daemon`/`*-request`/`owner-*`, o en la lista de supresión. https://www.rfc-editor.org/rfc/rfc3834
- Una respuesta automática por remitente cada 4 días (Gmail usa 4, el RFC 7) y 200 al día en total.
- La respuesta lleva `Auto-Submitted: auto-replied`, `X-Auto-Response-Suppress: All` (Exchange), `In-Reply-To`/`References`.

## Divulgación y traspaso
- Cada plantilla dice que contesta un agente de IA, «no una persona», y ofrece «responde HUMANO» (AI Act art. 50; §17941 de California).
- «HUMANO» (sin modelo), un id fuera del enum, JSON roto o Ghosty caído → plantilla de traspaso, hilo asignado al dueño
  del dominio y nota interna. Cobros, cuentas y quejas siempre a una persona (lo dice el prompt).
- Nunca revela si el remitente tiene cuenta, dominios o pagos: la respuesta es idéntica con o sin cuenta (OWASP).

## Operación
- No hay agente aparte: es Mascarito (`cmuq2rfma0008gewlanomot6g`) con un canal más. Las instrucciones del canal viven
  en `MAIL_INSTRUCTIONS` (`mascarito-mail.ts`) porque `ghosty/` no viaja en la imagen.
- Sin `GHOSTY_AGENT_ID`, todo correo recibe la plantilla de traspaso.
