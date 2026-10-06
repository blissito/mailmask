import { mock } from "node:test";
import type { MailMask } from "@easybits.cloud/mailmask";

export interface RecordedCall {
  method: string;
  args: unknown[];
}

type Impl = Record<string, (...args: unknown[]) => unknown>;

/**
 * Cliente de MailMask simulado para probar comandos sin pegarle a la red.
 * Cada llamada queda en `calls`; el valor (o el error) que devuelve lo decide
 * el test vía `impl`. Un método que el test no configuró revienta con un
 * mensaje claro — así una llamada que no se esperaba (p. ej. `dns.upsert`
 * después de que debió abortar por `managed: true`) no pasa inadvertida.
 */
export function fakeClient(impl: { domains?: Impl; dns?: Impl; apiKeys?: Impl } = {}): { client: MailMask; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  // `domains.list` casi todo comando lo llama primero (resolveDomainId): por
  // omisión devuelve [] para que un test que pasa ya el id (p. ej. "dom_1")
  // no tenga que configurarlo sólo para que resolveDomainId lo deje pasar.
  const domainsImpl: Impl = { list: () => [], ...impl.domains };
  function resource(name: string, methods: Impl = {}) {
    return new Proxy(
      {},
      {
        get(_target, prop: string) {
          return async (...args: unknown[]) => {
            calls.push({ method: `${name}.${prop}`, args });
            const fn = methods[prop];
            if (!fn) throw new Error(`fakeClient: ${name}.${prop} no se configuró en este test`);
            return fn(...args);
          };
        },
      },
    );
  }
  const client = {
    domains: resource("domains", domainsImpl),
    dns: resource("dns", impl.dns),
    apiKeys: resource("apiKeys", impl.apiKeys),
  } as unknown as MailMask;
  return { client, calls };
}

export class ExitSignal extends Error {
  constructor(public code: number) {
    super(`process.exit(${code})`);
  }
}

/**
 * Los comandos terminan errores con `process.exit` (vía `fail`/`failFromError`
 * en output.ts), que en un test de verdad mataría al runner. Se mockea para
 * que LANCE en vez de salir: así `assert.rejects(..., ExitSignal)` comprueba
 * el código Y, porque lanza, detiene el flujo igual que un `exit` real —
 * sin esto una mutación después de un "exit" simulado seguiría corriendo.
 */
export function trapExit(): void {
  mock.method(process, "exit", ((code?: number) => {
    throw new ExitSignal(code ?? 0);
  }) as never);
}
