# Short «Crea un correo nuevo en el dominio que ya tienes» — storytelling (para aprobar)

Campaña 1 de la serie «… en el dominio que ya tienes» (plan SB7 en `docs/campanas/correo-en-tu-dominio.md`).
Vertical 1080×1920, ~34 s, voz em_santa. Piel del sitio público: crema `#faf6ee`, rojo de máscara `#d7263d`,
dorado `#f2b705` sólo en la máscara, Bricolage Grotesque 800 + JetBrains Mono.

## Tres renglones

- **Abre:** «Tu tarjeta dice tuestudio.mx, pero tus cotizaciones salen desde gmail.com.»
- **Cierra (aprobado 21-oct-2026):** «Tu tarjeta y tu correo ya dicen tuestudio.mx, y un agente administra tu dominio. Crea tu correo gratis en mailmask.studio.»
- **Se lleva (bliss, literal):** «Cambias tus nameservers y ahora un agente puede administrar tu dominio y sus DNS automáticamente.»

## Circularidad

Abre con **la tarjeta de presentación** del estudio sobre un tapete de corte: el renglón web dice
`tuestudio.mx` y el renglón de correo dice `estudio.rios.2011@gmail.com`, con `gmail.com`
encendido en rojo. Cierra con **la misma tarjeta** en la misma posición: el renglón de correo ya dice
`hola@tuestudio.mx`, `tuestudio.mx` ahora va en rojo en los dos renglones (combinan) y una calcomanía
de la máscara queda pegada en la esquina. Un pósit rosa (el dorado es sólo de la máscara) sobre el renglón web dice «Lo siguiente: tu
página» y deja abierta la campaña 2 (página en el dominio con EasyBits).

## CTA

Verbo + URL + fecha: **«Crea tu correo gratis» · `mailmask.studio/correo-en-tu-dominio` · «hoy, 21 de octubre»**.
⚠️ La fecha es **provisional**: si el short no sale hoy, cambia en voz y pantalla.
La voz dice «mailmask punto studio»; la URL completa va en pantalla (decirla entera alarga 2 s).

## Lo que el short NO promete

- Gratis = hasta 5 direcciones, recibir y responder desde la Bandeja. **No** se dice que mandar correo nuevo sea gratis
  (eso pide el dominio activado, $99/mes) y no aparece ningún botón «Redactar» ni Apple Mail.
- El flujo que se enseña es delegar los nameservers a MailMask (`create_dns_zone`), no pegar registros a mano. Con la zona
  en MailMask sí es cierto que MailMask pone los registros y que el agente hace los cambios del dominio.
- No se enseñan nombres de nameservers en pantalla: Route53 los asigna por dominio.
- No se promete que el cambio sea inmediato: los nameservers tardan de 1 a 48 h.
- Vocabulario: «dirección», nunca «alias».
