import { log } from "./logger.js";

// Lazy-loaded AWS SDK clients (same pattern as ses.ts)
let _route53Domains: any;
let _route53: any;

async function getRoute53Domains() {
  if (!_route53Domains) {
    const { Route53DomainsClient } = await import("@aws-sdk/client-route-53-domains");
    // Route 53 Domains API is only available in us-east-1
    _route53Domains = new Route53DomainsClient({ region: "us-east-1" });
  }
  return _route53Domains;
}

async function getRoute53() {
  if (!_route53) {
    const { Route53Client } = await import("@aws-sdk/client-route-53");
    _route53 = new Route53Client({ region: "us-east-1" });
  }
  return _route53;
}

// --- WHOIS contact from env vars ---

function getRegistrantContact() {
  return {
    FirstName: process.env.REGISTRANT_FIRST_NAME ?? "MailMask",
    LastName: process.env.REGISTRANT_LAST_NAME ?? "Inc",
    Email: process.env.REGISTRANT_EMAIL ?? "admin@mailmask.studio",
    PhoneNumber: process.env.REGISTRANT_PHONE ?? "+52.5555555555",
    AddressLine1: process.env.REGISTRANT_ADDRESS ?? "Av. Reforma 222",
    City: process.env.REGISTRANT_CITY ?? "CDMX",
    State: process.env.REGISTRANT_STATE ?? "CDMX",
    CountryCode: (process.env.REGISTRANT_COUNTRY ?? "MX") as any,
    ZipCode: process.env.REGISTRANT_ZIP ?? "06600",
    ContactType: "COMPANY" as const,
    OrganizationName: "MailMask",
  };
}

// --- Check domain availability ---

export async function checkAvailability(domain: string): Promise<{ available: boolean; domain: string }> {
  const client = await getRoute53Domains();
  const { CheckDomainAvailabilityCommand } = await import("@aws-sdk/client-route-53-domains");

  const res = await client.send(new CheckDomainAvailabilityCommand({
    DomainName: domain,
  }));

  return {
    available: res.Availability === "AVAILABLE",
    domain,
  };
}

// --- Register domain ---

export async function registerDomain(domain: string): Promise<string> {
  const client = await getRoute53Domains();
  const { RegisterDomainCommand } = await import("@aws-sdk/client-route-53-domains");
  const contact = getRegistrantContact();

  const res = await client.send(new RegisterDomainCommand({
    DomainName: domain,
    DurationInYears: 1,
    AutoRenew: true,
    AdminContact: contact,
    RegistrantContact: contact,
    TechContact: contact,
    PrivacyProtectAdminContact: true,
    PrivacyProtectRegistrantContact: true,
    PrivacyProtectTechContact: true,
  }));

  const operationId = res.OperationId ?? "";
  log("info", "route53", "Domain registration submitted", { domain, operationId });
  return operationId;
}

// --- Get operation status ---

export async function getOperationStatus(operationId: string): Promise<"SUBMITTED" | "IN_PROGRESS" | "SUCCESSFUL" | "FAILED" | "ERROR"> {
  const client = await getRoute53Domains();
  const { GetOperationDetailCommand } = await import("@aws-sdk/client-route-53-domains");

  const res = await client.send(new GetOperationDetailCommand({
    OperationId: operationId,
  }));

  return (res.Status as any) ?? "ERROR";
}

// --- Create hosted zone ---

export async function createHostedZone(domain: string): Promise<{ hostedZoneId: string; nameservers: string[] }> {
  const client = await getRoute53();
  const { CreateHostedZoneCommand } = await import("@aws-sdk/client-route-53");

  const res = await client.send(new CreateHostedZoneCommand({
    Name: domain,
    CallerReference: `mailmask-${domain}-${Date.now()}`,
    HostedZoneConfig: {
      Comment: `Managed by MailMask for ${domain}`,
    },
  }));

  const hostedZoneId = res.HostedZone?.Id?.replace("/hostedzone/", "") ?? "";
  const nameservers = res.DelegationSet?.NameServers ?? [];

  log("info", "route53", "Hosted zone created", { domain, hostedZoneId, nameservers });
  return { hostedZoneId, nameservers };
}

// --- Configure DNS records (MX, TXT, DKIM CNAMEs, SPF) ---

export async function configureDnsRecords(
  hostedZoneId: string,
  domain: string,
  verificationToken: string,
  dkimTokens: string[],
): Promise<void> {
  const client = await getRoute53();
  const { ChangeResourceRecordSetsCommand } = await import("@aws-sdk/client-route-53");

  const changes: any[] = [
    // MX record pointing to SES inbound
    {
      Action: "UPSERT",
      ResourceRecordSet: {
        Name: domain,
        Type: "MX",
        TTL: 300,
        ResourceRecords: [
          { Value: `10 inbound-smtp.${process.env.AWS_SES_INBOUND_REGION ?? "us-east-1"}.amazonaws.com` },
        ],
      },
    },
    // TXT record for SES domain verification
    {
      Action: "UPSERT",
      ResourceRecordSet: {
        Name: `_amazonses.${domain}`,
        Type: "TXT",
        TTL: 300,
        ResourceRecords: [
          { Value: `"${verificationToken}"` },
        ],
      },
    },
    // SPF record
    {
      Action: "UPSERT",
      ResourceRecordSet: {
        Name: domain,
        Type: "TXT",
        TTL: 300,
        ResourceRecords: [
          { Value: `"v=spf1 include:amazonses.com ~all"` },
        ],
      },
    },
  ];

  // DKIM CNAME records
  for (const token of dkimTokens) {
    changes.push({
      Action: "UPSERT",
      ResourceRecordSet: {
        Name: `${token}._domainkey.${domain}`,
        Type: "CNAME",
        TTL: 300,
        ResourceRecords: [
          { Value: `${token}.dkim.amazonses.com` },
        ],
      },
    });
  }

  await client.send(new ChangeResourceRecordSetsCommand({
    HostedZoneId: hostedZoneId,
    ChangeBatch: {
      Comment: `MailMask email setup for ${domain}`,
      Changes: changes,
    },
  }));

  log("info", "route53", "DNS records configured", { domain, hostedZoneId, records: changes.length });
}

// --- Update nameservers (point registered domain to hosted zone NS) ---

export async function updateNameservers(domain: string, nameservers: string[]): Promise<void> {
  const client = await getRoute53Domains();
  const { UpdateDomainNameserversCommand } = await import("@aws-sdk/client-route-53-domains");

  await client.send(new UpdateDomainNameserversCommand({
    DomainName: domain,
    Nameservers: nameservers.map((ns) => ({ Name: ns })),
  }));

  log("info", "route53", "Nameservers updated", { domain, nameservers });
}
