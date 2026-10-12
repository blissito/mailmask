# Pruebas de `auth.ts`

Cómo se prueban las contraseñas, el JWT de sesión, el turn token `mt_` del asistente y las
cookies con funciones puras, la SQLite de pruebas y nada de red. Nace de `auth.test.ts`.

## Lo caro se paga una vez: PBKDF2 son 600 000 iteraciones

`hashPassword` y el camino «contraseña correcta» de `verifyPassword` cuestan 600 000
iteraciones de PBKDF2 cada uno. En la suite eso no es gratis:

- Guarda UN hash en el `before()` y dispara contra él la contraseña correcta y la incorrecta;
  no llames a `hashPassword` por prueba.
- Un usuario que sólo tiene que EXISTIR (el `mt_` vigente, la sesión válida, el corte por
  cambio de contraseña) se crea con un `passwordHash` de relleno —
  `createUser(correo, "no-usado:0000")`—: nadie lo verifica y se ahorra medio segundo.

## `deriveKey` no se exporta: los casos límite se fabrican con `crypto.subtle`

- **Hash legado (`needsRehash: true`)**: PBKDF2-SHA256 a **1 000 iteraciones**, salt aleatorio
  de 16 bytes, en el mismo formato `saltHex:hashHex`. `verifyPassword` lo reconoce por su camino
  de respaldo y devuelve `{ valid: true, needsRehash: true }`.
- **Token de otro secreto**: `JWT_SECRET` se lee **al importar** y la `CryptoKey` se cachea, así
  que cambiar el env no sirve. Se firma a mano un HS256 con `crypto.subtle` y **otra** llave.
- **Vencido**: `exp < now` es **estricto**, así que `signJwt(payload, 0)` sigue vigente (ese es
  su propio caso, no el del vencido); el vencido se pide con ttl negativo (`signJwt(payload, -1)`).
- **Alterado**: toca la **primera** letra de la firma, nunca la última. En base64url el último
  carácter lleva bits de relleno, así que cambiarlo puede decodificar a los **mismos** bytes y
  dejar la firma válida: la prueba pasa o falla al azar según la firma que tocó.

## `Secure` se decide al importar, con `FLY_APP_NAME`, que en pruebas no existe

`IS_PROD` se resuelve **al cargar el módulo**, así que en la caja la cookie de sesión y la de
CSRF salen **sin `Secure`**. La prueba lo afirma así y lo dice en su nombre: no es una bandera
olvidada, es el entorno de pruebas.

## Revocar por cambio de contraseña sin congelar el reloj

`iat` va en segundos y `passwordChangedAt` en milisegundos ISO; si ambos caen en el mismo
segundo, `iat < changedAtSec` es falso y el token NO se revoca. Para probarlo de forma
determinista se fecha el cambio **adelante** (`new Date(Date.now() + 60_000).toISOString()`) con
un update directo a `users` — nunca con `mock.method(Date, "now")`, que no mueve `new Date()`.

## Los dos cruces del `mt_`

El turn token se acuña con el **mismo secreto** que la sesión, así que lo único que los separa
es el `aud`. Vale un caso por lado — y hay que armarlos con cuidado, porque un cruce mal armado
se lee como un acierto:

- **Cookie de sesión con el JWT de un `mt_`**: pon el token **sin el prefijo `mt_`**
  (`mt.slice(3)`). Con el prefijo, `verifyJwt` truena por la firma y devuelve null por el motivo
  equivocado —la prueba queda verde pase lo que pase, incluso si se comenta la línea que
  defiende el cruce—; sin él verifica bien y quien lo detiene es el `if (payload.aud !== undefined)`
  de `getAuthUser`, que es justo la defensa que se quiere cubrir.
- **`mt_` con un JWT de sesión** (sin `aud`) → `verifyTurnToken` null: ése sí pasa por el `aud`.
