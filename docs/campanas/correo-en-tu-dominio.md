# Campaña 1 — «Crea un correo nuevo en el dominio que ya tienes» (21-oct-2026)

Serie «… en el dominio que ya tienes». Campaña 2: «Crea una página en el dominio que ya tienes» (EasyBits).
Método: **StoryBrand SB7** (Donald Miller). Las cuatro piezas cuentan la misma historia.

## Audiencia (aprobada por bliss, 21-oct-2026)
Dueños de negocio chico y freelancers en México, de 30 a 50 años, que viven en el celular y ya pagan un dominio para su web (Wix, Hostinger, GoDaddy). **Casi no leen: miran.** Nada técnico en la copia (sin DNS, MX ni DKIM). Cada pantalla lleva una ilustración animada grande, un párrafo corto y una frase destacada.

## SB7
| Parte | Contenido |
|---|---|
| Personaje | Freelancer o negocio chico que **ya tiene dominio** (su web vive ahí) y sigue escribiendo desde Gmail. |
| Problema externo | Su dominio no tiene correo. |
| Problema interno | «Mandar una cotización desde un @gmail se ve poco serio.» |
| Problema filosófico | Si el dominio ya es tuyo, tu correo también debería serlo. |
| Guía | MailMask: empatía («a todos nos pasó») + autoridad (DNS configurado solo, Bandeja, clientes reales). |
| Plan (3 pasos) | 1. Escribes tu dominio. 2. Copias cinco registros DNS: MX, TXT y 3 CNAME de DKIM (o los pone MailMask). 3. Creas `hola@tudominio`. |
| Llamado a la acción | Directo: «Crea tu correo gratis». De transición: guía «Cómo tener correo con tu dominio». |
| Fracaso | Más cotizaciones que salen desde el Gmail y más clientes que dudan. |
| Éxito | Su primera respuesta firmada desde `hola@tudominio`, recibida en la Bandeja. |

**Lo que sí cumple el plan gratis**: hasta 5 direcciones; recibe y responde desde la Bandeja. **Mandar correo nuevo** (API, Redactar, Apple Mail) pide el dominio activado ($99/mes). La copia no promete más que eso.
**Ojo con el MX**: si el dominio ya tiene correo en otro proveedor, apuntarlo aquí lo mueve. La landing lo avisa.

## Piezas de hoy
1. **Landing** `public/correo-en-tu-dominio.html`, con el tema público (crema y rojo, tokens): hero con la frase, el plan en 3 pasos, antes/después (Gmail contra el dominio), FAQ y JSON-LD. La hago yo.
2. **Correo a la base**: a las cuentas con dominio que tienen 0 direcciones. Un solo CTA a la landing. Lo hago yo, después de la landing.
3. **Short vertical** con un subagente: storytelling y guion → **aprobación de bliss** → style frames → render. Carpeta `videos/short-correo-en-tu-dominio/`. Debe verse distinto del `short-01-gmail-personal` (mismo tema, otro molde).
4. **Post** para LinkedIn y X con el guion del short. Sale al final.

## Por decidir
- URL y fecha del CTA. Propuesta: `mailmask.studio/correo-en-tu-dominio`, «hoy, 21 de octubre».
- ¿Hay oferta con fecha límite o sólo «empieza gratis»? No se inventa ninguna oferta.
- El cierre deja abierta la campaña 2: «tu dominio ya es tu correo. Lo siguiente: tu página».
