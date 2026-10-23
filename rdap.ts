// RDAP (el WHOIS en JSON) del registro de un dominio: registrador, alta, vencimiento, estados y NS.
// Es HTTP puro, sin librería de WHOIS. Lo usan el transfer-in (edad y candado) y el agente.

export interface RdapInfo {
  registrar: string | null;
  createdAt: string | null;
  expiresAt: string | null;
  /** Estados EPP tal cual los da el registro («client transfer prohibited», …). */
  statuses: string[];
  nameservers: string[];
}

/** null si RDAP no respondió con JSON (dominio inexistente, TLD sin RDAP o red). */
export async function fetchRdap(domain: string, timeoutMs = 12_000): Promise<RdapInfo | null> {
  const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    headers: {
      accept: "application/rdap+json",
      // Sin User-Agent, Cloudflare contesta 403 con una página HTML y el JSON.parse
      // revienta. La consulta fallaba SIEMPRE y todos los requisitos salían como "?".
      "user-agent": "MailMask/1.0 (+https://www.mailmask.studio)",
    },
    signal: AbortSignal.timeout(timeoutMs),
    redirect: "follow",
  });
  if (!res.ok || !(res.headers.get("content-type") ?? "").includes("json")) return null;
  return parseRdap(await res.json());
}

export function parseRdap(j: any): RdapInfo {
  const event = (action: string) => (j.events ?? []).find((e: any) => e.eventAction === action)?.eventDate ?? null;
  return {
    registrar: (j.entities ?? []).find((e: any) => (e.roles ?? []).includes("registrar"))?.vcardArray?.[1]
      ?.find((v: any[]) => v[0] === "fn")?.[3] ?? null,
    createdAt: event("registration"),
    expiresAt: event("expiration"),
    statuses: j.status ?? [],
    nameservers: (j.nameservers ?? []).map((n: any) => String(n.ldhName ?? "").toLowerCase()).filter(Boolean),
  };
}
