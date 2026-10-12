# Landing de dominios (`public/dominios.html`, ruta `/dominios`)

**Qué:** por qué la página que vende registrar y transferir dominios **no publica ninguna cifra
por extensión**, y qué se puede tocar sin romper esa regla.

## La decisión

`/dominios` no muestra precios de TLD. El único endpoint que los da
(`GET /api/domains/tlds`, `main.ts`) **exige sesión**, así que una página pública sólo podría
tenerlos copiados a mano — y quedaría como segunda fuente frente a `TLD_PRICES` (`db.ts`). Ya
pasó: la página anunciaba «desde $549» mientras la tabla cobraba 899.

En vez de una tabla, la página manda al buscador: **el precio de tu dominio lo ves al buscarlo**,
antes de pagar. Si algún día se quiere la tabla pública, primero hay que abrir un endpoint
público de precios (cambio de API y de seguridad: otro pedido).

## La única cifra permitida

El plan **anual del dominio activado**, `DOMAIN_ANNUAL_PRICE` de `plans.ts` (hoy $999). Va
amarrada por prueba: `dominios-seo.test.ts` exige que **todo** `$<dígitos>` del cuerpo de la
página sea exactamente ese valor y que **ninguno** de los `userMxnCents`/`transferMxnCents` de
`TLD_PRICES` aparezca formateado como pesos. Cambiar un precio en `plans.ts` sin tocar la página
hace fallar la suite, y al revés también.

Por eso en la página no se escribe `$99` (el mes del dominio activado) ni un `$0`: cualquier
cifra nueva en pesos tiene que salir de `plans.ts` o la prueba truena.

Tampoco se **compara** transferir con renovar. `TLD_PRICES` cobra lo mismo por las dos cosas en
casi todas las extensiones, y en `.click`/`.link` la transferencia cuesta más (229 frente a
109/139). Decir «transferir sale más barato» es la misma promesa sin fuente que una cifra
inventada, así que `dominios-seo.test.ts` la caza: si la frase aparece, exige que alguna extensión
de verdad lo cumpla.

## La transferencia se describe tal como es

La sección de transferir sigue el flujo real de `domain-transfer.ts`, no el de un folleto:

- Los requisitos se comprueban **antes de cobrar** (`checkDomainReadiness`): transferibilidad
  según AWS, más de 60 días (regla ICANN), candado de transferencia apagado —todo consultado—, y
  dos que sólo puede confirmar el cliente (privacidad WHOIS apagada, correo del contacto
  administrativo accesible).
- El código EPP se guarda **cifrado** y se borra cuando el registrador acepta la solicitud.
- La solicitud tarda **5 a 7 días** y depende de que el cliente apruebe el correo del registrador.
- **Nada se mueve sin el inventario de DNS aprobado**: si se cambian los nameservers con la zona
  vacía, la web y el correo del cliente mueren en el acto.

Son **dos relojes distintos** y confundirlos cuenta una historia falsa: los 5 a 7 días son de la
solicitud y corren desde que el cliente aprueba el correo del registrador, no desde que aprueba el
inventario de DNS. Los nameservers se mueven cuando ocurren **las dos cosas**: el traspaso
terminado y el inventario aprobado (`finalizeDomainRegistration` en `domain-provision.ts` no toca
nada mientras `dnsImportStatus !== "approved"` y avisa a los 3 días de espera).

El inventario tampoco es «tus registros entran, nada se pierde»: `snapshotDns` (`dns-import.ts`)
lee una lista de nombres comunes en el DNS público y el propio código pide revisarlos a mano, así
que la página lo ofrece como **borrador que el cliente corrige antes de aprobar**.

Si el flujo cambia, esta ficha y la sección de la página se mueven juntas.

## Dónde vive todo

La ruta se sirve en `main.ts` (junto a `/bandeja-compartida`) y está en `exclude.paths` del
OpenAPI, así que no sale en `/openapi.json`. Va en **dos lados** del sitemap —la fila de
`paginas` en `scripts/gen-sitemap.ts` y su `<url>` en `public/sitemap.xml`— porque el generador
borra en silencio lo que no esté en la lista, y el footer de `public/landing.html` la enlaza para
que no quede huérfana. Su imagen social es propia (`public/img/og-dominios.jpg`, desde
`scripts/og-dominios.html`), como la de las demás páginas del sitemap: reglas comunes y el resto
de la trampa, en [SEO de páginas públicas](seo-paginas-publicas.md).
