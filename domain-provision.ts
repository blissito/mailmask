// Aprovisionamiento de un dominio recién registrado o recién transferido: hosted zone,
// nameservers, verificación en SES, registros de correo y fila en `domains`.
//
// Vive fuera de `cron.ts` porque tiene que ser **idempotente**: antes era una secuencia de
// ocho pasos sin persistencia intermedia, así que un fallo a mitad dejaba la fila en
// `registering` y al minuto siguiente el cron repetía el paso 1 — creando otra hosted zone
// cada vez. Ahora cada paso guarda lo suyo y se salta si ya está hecho.
import { log } from "./logger.js";
import {
  createDomain,
  getDomainRegistrationsByStatus,
  getDomainByName,
  updateDomain,
  updateDomainRegistration,
  type DomainRegistration,
} from "./db.js";

/** Tras esto, seguir reintentando cada minuto sólo gasta llamadas a AWS. */
const LIMITE_REINTENTOS_MS = 2 * 3600_000;
/** Un transfer completado que espera la aprobación del inventario de DNS del cliente. */
const ESPERA_APROBACION_DNS_MS = 3 * 864e5;
/** Un transfer pagado que nunca llegó a mandarse a AWS (el auth code caduca en 1 h). */
const ESPERA_AUTH_CODE_MS = 864e5;

export async function finalizeDomainRegistration(reg: DomainRegistration): Promise<void> {
  const {
    ensureHostedZone, updateNameservers, configureDnsRecords, getDomainDetail,
  } = await import("./route53.js");
  const { verifyDomain, createReceiptRule, sendAlert } = await import("./ses.js");

  // Un transfer-in llega con el dominio ya en producción para alguien: si el inventario de
  // DNS no está aprobado, cambiar los nameservers le tumba la web y el correo.
  if (reg.kind === "transfer" && reg.dnsImportStatus !== "approved") {
    updateDomainRegistration(reg.id, { lastError: "dns_snapshot_no_aprobado" });
    log("warn", "route53", "Transfer sin inventario DNS aprobado; no se toca nada", { domain: reg.domainName });
    // Esperar es correcto, pero esperar en silencio para siempre no: el dominio ya está en
    // nuestra cuenta y el cliente no ha aprobado nada.
    const desde = Date.parse(reg.transferApprovedAt ?? reg.createdAt);
    if (Number.isFinite(desde) && Date.now() - desde > ESPERA_APROBACION_DNS_MS && reg.warnedAt !== "dns") {
      updateDomainRegistration(reg.id, { warnedAt: "dns" });
      await sendAlert(
        "transferencia-sin-aprobar-dns",
        `${reg.domainName} (${reg.ownerEmail}) lleva más de 3 días transferido y sin aprobar su inventario de DNS. Hasta que lo apruebe no se toca su zona, así que el dominio está en el limbo: escríbele.`,
      );
    }
    return;
  }

  // El dominio puede estar ya dado de alta en OTRA cuenta: agregar un dominio no exige
  // probar que es tuyo, sólo que nadie lo tenga. Sin esta comprobación, el transfer-in del
  // dueño real activaba el dominio en la cuenta que se le adelantó y quien pagó se quedaba
  // sin nada. Va antes de tocar AWS: aquí todavía no se ha movido nada.
  const existente = getDomainByName(reg.domainName);
  if (existente && existente.ownerEmail !== reg.ownerEmail) {
    updateDomainRegistration(reg.id, { lastError: "dominio_en_otra_cuenta" });
    await sendAlert(
      "dominio-en-otra-cuenta",
      `${reg.domainName} lo pagó ${reg.ownerEmail}, pero la fila de \`domains\` es de ${existente.ownerEmail}. No se tocó nada: hay que resolver a mano quién se queda con el dominio.`,
    );
    log("error", "route53", "El dominio ya está en otra cuenta; aprovisionamiento detenido", { domain: reg.domainName });
    return;
  }

  // 1. Hosted zone. `ensureHostedZone` adopta la existente en vez de duplicarla, y el id se
  //    persiste antes de nada más para que un fallo posterior no la deje huérfana.
  let hostedZoneId = reg.hostedZoneId ?? "";
  let nameservers: string[] = [];
  const zona = await ensureHostedZone(reg.domainName);
  hostedZoneId = zona.hostedZoneId;
  nameservers = zona.nameservers;
  if (reg.hostedZoneId !== hostedZoneId) {
    updateDomainRegistration(reg.id, { hostedZoneId });
  }

  // 1bis. En un transfer-in, la zona se puebla ANTES de que nadie nos pregunte. Si el
  //       cliente delegara con la zona vacía, su web y su correo mueren en el acto.
  if (reg.kind === "transfer" && reg.dnsSnapshot?.length) {
    const { applyRecordChanges } = await import("./route53.js");
    const apex = reg.domainName.toLowerCase();
    const { dropCnameConflicts } = await import("./dns-records.js");
    const copyable = dropCnameConflicts(reg.dnsSnapshot).filter((r) => !(r.name === apex && (r.type === "NS" || r.type === "SOA")));
    // Route 53 acepta 1000 cambios por lote, pero de 100 en 100 un fallo cuesta menos.
    for (let i = 0; i < copyable.length; i += 100) {
      await applyRecordChanges(
        hostedZoneId,
        copyable.slice(i, i + 100).map((rrset) => ({ action: "UPSERT" as const, rrset })),
        `Inventario aprobado de ${reg.domainName}`,
      );
    }
    log("info", "route53", "Inventario DNS restaurado", { domain: reg.domainName, registros: copyable.length });
  }

  // 2. Apuntar el dominio a nuestra zona. Idempotente: si ya apunta, no se toca.
  const detalle = await getDomainDetail(reg.domainName).catch(() => null);
  const yaApunta = detalle && nameservers.length &&
    nameservers.every((ns) => detalle.nameservers.some((n) => n.toLowerCase() === ns.toLowerCase()));
  if (!yaApunta && nameservers.length) {
    await updateNameservers(reg.domainName, nameservers);
  }

  // 3. Identidad y tokens de SES.
  const dnsRecords = await verifyDomain(reg.domainName);

  // 4. Registros de correo, fusionando con lo que la zona ya tuviera.
  const { mxOurs } = await configureDnsRecords(
    hostedZoneId,
    reg.domainName,
    dnsRecords.verificationToken,
    dnsRecords.dkimTokens,
    { keepForeignMx: reg.kind === "transfer" },
  );

  // 5. Regla de recepción. No fatal: puede faltar SNS_TOPIC_ARN.
  try {
    await createReceiptRule(reg.domainName);
  } catch (err: any) {
    log("warn", "route53", "Receipt rule creation failed (non-fatal)", { domain: reg.domainName, error: String(err) });
  }

  // 6. Fila en `domains`, reusándola si ya existe (reintento).
  const domainRow = existente ??
    createDomain(reg.ownerEmail, reg.domainName, dnsRecords.dkimTokens, dnsRecords.verificationToken);

  updateDomain(domainRow.id, {
    verified: true,
    mxConfigured: mxOurs,
    registeredViaMailmask: true,
    hostedZoneId,
    dnsZoneStatus: "active",
    dnsNameservers: nameservers,
    dnsDelegatedAt: new Date().toISOString(),
  });

  // 7. La fecha de expiración la dice AWS. Antes se inventaba con `Date.now() + 365 días`,
  //    y toda la ventana de cobro de la renovación se calcula contra ella.
  const expiresAt = detalle?.expirationDate
    ?? (await getDomainDetail(reg.domainName).catch(() => null))?.expirationDate
    ?? null;
  if (!expiresAt) {
    await sendAlert("dominio-sin-expiracion", `No se pudo leer la fecha de expiración de ${reg.domainName} en AWS. Revísala a mano: de ella depende el cobro de la renovación.`);
  }

  updateDomainRegistration(reg.id, {
    status: "registered",
    domainId: domainRow.id,
    hostedZoneId,
    registeredAt: new Date().toISOString(),
    expiresAt,
    awsAutoRenew: true,
    lastSyncedAt: new Date().toISOString(),
    lastError: null,
  });

  try {
    const { sendTemplate, domainRegistered, domainTransferCompleted } = await import("./emails.js");
    await sendTemplate(
      reg.ownerEmail,
      reg.kind === "transfer"
        ? domainTransferCompleted({ domain: reg.domainName, expiresAt })
        : domainRegistered({ domain: reg.domainName, expiresAt }),
    );
  } catch (err) {
    log("error", "route53", "No se pudo avisar del alta del dominio", { domain: reg.domainName, error: String(err) });
  }

  log("info", "route53", "Domain provisioning completed", { domain: reg.domainName, domainId: domainRow.id, expiresAt });
}

/** Un fallo repetido no se reintenta para siempre: pasa a `failed` y avisa. */
export async function marcarFalloDeAprovisionamiento(reg: DomainRegistration, error: string): Promise<void> {
  const { sendAlert } = await import("./ses.js");
  const desde = Date.parse(reg.registeredAt ?? reg.createdAt);
  const agotado = Number.isFinite(desde) && Date.now() - desde > LIMITE_REINTENTOS_MS;

  if (agotado) {
    updateDomainRegistration(reg.id, { status: "failed", lastError: error });
    await sendAlert("dominio-aprovisionamiento", `El aprovisionamiento de ${reg.domainName} lleva más de 2 h fallando y se detuvo:\n\n${error}`);
    log("error", "route53", "Provisioning gave up", { domain: reg.domainName, error });
  } else {
    updateDomainRegistration(reg.id, { lastError: error });
    log("error", "route53", "Provisioning error, will retry", { domain: reg.domainName, error });
  }
}

/**
 * Manda la solicitud de transferencia a AWS. Se llama cuando entra el pago, y también
 * cuando el cliente vuelve a mandar el auth code porque el de la primera vez ya caducó.
 */
export async function iniciarTransferencia(reg: DomainRegistration): Promise<void> {
  const { takeAuthCode, forgetAuthCode } = await import("./domain-transfer.js");
  const { transferDomain } = await import("./route53.js");
  const { nameserversActuales } = await import("./dns-import.js");
  const { sendTemplate, domainTransferStarted, domainTransferPending } = await import("./emails.js");

  const authCode = takeAuthCode(reg.id);
  if (!authCode) {
    // El código caduca a los 7 días o no se pudo descifrar: hay que pedirlo otra vez.
    log("warn", "route53", "Transferencia sin auth code vigente", { domain: reg.domainName });
    await sendTemplate(reg.ownerEmail, domainTransferPending({ domain: reg.domainName, daysWaiting: 0 }))
      .catch(() => {});
    return;
  }

  // Se mandan los nameservers ACTUALES del cliente: si no, AWS pone los suyos al completarse
  // y el dominio se queda sin DNS de golpe. Así el transfer no cambia nada, y la migración a
  // nuestra zona la hacemos después, con la zona ya poblada.
  const ns = await nameserversActuales(reg.domainName).catch(() => [] as string[]);

  try {
    // El contacto es el del cliente: el dominio ya era suyo antes de llegar aquí.
    const operationId = await transferDomain(reg.domainName, authCode, ns, reg.whoisContact ?? undefined);
    updateDomainRegistration(reg.id, {
      status: "transfer_submitted",
      route53OperationId: operationId,
      transferRequestedAt: new Date().toISOString(),
      lastError: null,
    });
    forgetAuthCode(reg.id);
    await sendTemplate(reg.ownerEmail, domainTransferStarted({ domain: reg.domainName })).catch(() => {});
    log("info", "route53", "Transfer submitted", { domain: reg.domainName, operationId, nsPropios: ns.length });
  } catch (err) {
    forgetAuthCode(reg.id);
    updateDomainRegistration(reg.id, { status: "transfer_failed", lastError: String(err) });
    const { sendAlert } = await import("./ses.js");
    await sendAlert("transferencia-fallida", `AWS rechazó la transferencia de ${reg.domainName} (${reg.ownerEmail}):\n\n${String(err)}\n\nYa se le cobró: hay que reembolsarle.`);
    const { domainTransferFailed } = await import("./emails.js");
    await sendTemplate(reg.ownerEmail, domainTransferFailed({ domain: reg.domainName, reason: null })).catch(() => {});
  }
}

/** Recordatorios de aprobación: AWS caduca la solicitud sola a los ~5 días en muchos TLDs. */
const HITOS_RECORDATORIO = [2, 5, 8];
const DIAS_HASTA_CANCELAR = 10;

/**
 * Pagadas y sin mandar a AWS. Pasa cuando el auth code caducó (7 días) o no se pudo
 * descifrar: `iniciarTransferencia` manda el correo de "mándalo otra vez" y ahí
 * se quedaba, porque ningún cron miraba este estado. Cobrado y sin transferencia.
 */
async function avisarTransferenciasPagadasSinMandar(): Promise<void> {
  const { sendAlert } = await import("./ses.js");
  const { sendTemplate, domainTransferPending } = await import("./emails.js");

  for (const reg of getDomainRegistrationsByStatus("transfer_paid")) {
    if (Date.now() - Date.parse(reg.createdAt) < ESPERA_AUTH_CODE_MS) continue;
    if (reg.warnedAt === "sin-auth-code") continue;
    updateDomainRegistration(reg.id, { warnedAt: "sin-auth-code" });
    await sendTemplate(reg.ownerEmail, domainTransferPending({ domain: reg.domainName, daysWaiting: 1 })).catch(() => {});
    await sendAlert(
      "transferencia-pagada-sin-mandar",
      `${reg.ownerEmail} pagó la transferencia de ${reg.domainName} hace más de un día y nunca se mandó a AWS: falta que vuelva a mandar su código EPP. Si no contesta, hay que reembolsarle.`,
    );
  }
}

/** Sondea las transferencias en curso. */
export async function sondearTransferencias(): Promise<void> {
  await avisarTransferenciasPagadasSinMandar();

  const enCurso = [
    ...getDomainRegistrationsByStatus("transfer_submitted"),
    ...getDomainRegistrationsByStatus("transfer_awaiting_approval"),
  ];
  if (!enCurso.length) return;

  const { getOperationStatus, getDomainDetail } = await import("./route53.js");
  const { sendTemplate, domainTransferPending, domainTransferDnsReview, domainTransferFailed } = await import("./emails.js");
  const { sendAlert } = await import("./ses.js");

  for (const reg of enCurso) {
    if (!reg.route53OperationId) continue;
    try {
      const estado = await getOperationStatus(reg.route53OperationId);

      if (estado === "SUCCESSFUL") {
        const detalle = await getDomainDetail(reg.domainName).catch(() => null);
        updateDomainRegistration(reg.id, {
          status: "registering",
          transferApprovedAt: new Date().toISOString(),
          expiresAt: detalle?.expirationDate ?? reg.expiresAt,
        });
        log("info", "route53", "Transfer completed, entra al aprovisionamiento", { domain: reg.domainName });

        // El aprovisionamiento se detiene solo si el inventario no está aprobado; el aviso
        // es para que el cliente vaya a aprobarlo.
        if (reg.dnsImportStatus !== "approved") {
          await sendTemplate(reg.ownerEmail, domainTransferDnsReview({
            domain: reg.domainName,
            recordCount: reg.dnsSnapshot?.length ?? 0,
            reviewUrl: `${process.env.APP_URL ?? "https://www.mailmask.studio"}/app`,
          })).catch(() => {});
        }
        continue;
      }

      if (estado === "FAILED" || estado === "ERROR") {
        updateDomainRegistration(reg.id, { status: "transfer_failed", lastError: `Route 53 operation ${estado}` });
        await sendTemplate(reg.ownerEmail, domainTransferFailed({ domain: reg.domainName, reason: null })).catch(() => {});
        await sendAlert("transferencia-fallida", `La transferencia de ${reg.domainName} (${reg.ownerEmail}) terminó en ${estado}. Ya se le cobró: hay que reembolsarle.`);
        continue;
      }

      // En curso: esperando a que el cliente conteste el correo de su registrador.
      if (reg.status === "transfer_submitted") {
        updateDomainRegistration(reg.id, { status: "transfer_awaiting_approval" });
      }

      const esperando = reg.transferRequestedAt
        ? Math.floor((Date.now() - Date.parse(reg.transferRequestedAt)) / 864e5)
        : 0;

      if (esperando >= DIAS_HASTA_CANCELAR) {
        updateDomainRegistration(reg.id, { status: "transfer_cancelled", lastError: "Sin aprobación del registrador" });
        await sendTemplate(reg.ownerEmail, domainTransferFailed({
          domain: reg.domainName,
          reason: "No se aprobó a tiempo en tu registrador actual",
        })).catch(() => {});
        await sendAlert("transferencia-cancelada", `${reg.domainName} (${reg.ownerEmail}) llevaba ${esperando} días sin aprobación. Hay que reembolsarle.`);
      } else if (HITOS_RECORDATORIO.includes(esperando) && reg.warnedAt !== String(esperando)) {
        await sendTemplate(reg.ownerEmail, domainTransferPending({ domain: reg.domainName, daysWaiting: esperando })).catch(() => {});
        updateDomainRegistration(reg.id, { warnedAt: String(esperando) });
      }
    } catch (err) {
      log("error", "route53", "Sondeo de transferencia falló", { domain: reg.domainName, error: String(err) });
      updateDomainRegistration(reg.id, { lastError: String(err) });
    }
  }
}
