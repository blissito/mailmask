/**
 * Comprueba que `dist/` sigue publicando la MISMA API que antes del cambio a TypeScript 7.
 *
 * Por qué así: con TS 7 tsup ya no genera los tipos (el `tsc` nativo no expone la API JS de
 * TypeScript). `dist/index.d.ts` deja de ser un bundle con todo inline y pasa a ser un índice
 * que sólo reexporta (`export * from "./client.js"`), así que comparar su texto daría falso
 * rojo, y un grep de nombres no prueba nada. Aquí importa de `dist/` de verdad y deja que el
 * compilador resuelva los tipos publicados: si un nombre desaparece o deja de ser valor,
 * `tsc --noEmit -p scripts/tsconfig.json` falla.
 *
 * Referencia: `scripts/exports-reference.json` — los 90 exports de `dist/index.d.ts` en `main`
 * antes del cambio (TypeScript 5.9.3, 2026-10-11).
 *
 * Uso: `npm run check:exports` (necesita `npm run build` antes).
 */
import * as sdk from "../dist/index.js";

/* --- Tipos publicados (89) --- */
type T_AccountExport = sdk.AccountExport;
type T_AccountMe = sdk.AccountMe;
type T_AccountMeDomainUsage = sdk.AccountMeDomainUsage;
type T_AccountProfile = sdk.AccountProfile;
type T_Addon = sdk.Addon;
type T_AddonsResponse = sdk.AddonsResponse;
type T_Address = sdk.Address;
type T_AddressCreated = sdk.AddressCreated;
type T_Alias = sdk.Alias;
type T_AliasCreated = sdk.AliasCreated;
type T_ApiKey = sdk.ApiKey;
type T_AttachmentRef = sdk.AttachmentRef;
type T_BillingStatus = sdk.BillingStatus;
type T_BulkJob = sdk.BulkJob;
type T_BulkJobCreated = sdk.BulkJobCreated;
type T_BulkSendInput = sdk.BulkSendInput;
type T_CannedReply = sdk.CannedReply;
type T_CheckoutLink = sdk.CheckoutLink;
type T_CreateAddressInput = sdk.CreateAddressInput;
type T_CreateAliasInput = sdk.CreateAliasInput;
type T_CreateRuleInput = sdk.CreateRuleInput;
type T_CreateWebhookInput = sdk.CreateWebhookInput;
type T_DnsChangeResult = sdk.DnsChangeResult;
type T_DnsDelegation = sdk.DnsDelegation;
type T_DnsImportResult = sdk.DnsImportResult;
type T_DnsListResponse = sdk.DnsListResponse;
type T_DnsPreset = sdk.DnsPreset;
type T_DnsRecord = sdk.DnsRecord;
type T_DnsRecordType = sdk.DnsRecordType;
type T_DnsRRSet = sdk.DnsRRSet;
type T_DnsRRSetAnotado = sdk.DnsRRSetAnotado;
type T_DnsSetup = sdk.DnsSetup;
type T_DnsSetupRecord = sdk.DnsSetupRecord;
type T_DnsZoneCreated = sdk.DnsZoneCreated;
type T_DnsZoneState = sdk.DnsZoneState;
type T_Domain = sdk.Domain;
type T_DomainCreated = sdk.DomainCreated;
type T_DomainInvite = sdk.DomainInvite;
type T_DomainMember = sdk.DomainMember;
type T_DomainRegistration = sdk.DomainRegistration;
type T_DomainRegistrationCreated = sdk.DomainRegistrationCreated;
type T_DomainSearchResult = sdk.DomainSearchResult;
type T_DomainVerification = sdk.DomainVerification;
type T_EmailLog = sdk.EmailLog;
type T_InboxAttachment = sdk.InboxAttachment;
type T_InboxComposeInput = sdk.InboxComposeInput;
type T_InboxConversation = sdk.InboxConversation;
type T_InboxConversationDetail = sdk.InboxConversationDetail;
type T_InboxListOptions = sdk.InboxListOptions;
type T_InboxMessage = sdk.InboxMessage;
type T_InboxNote = sdk.InboxNote;
type T_InboxPage = sdk.InboxPage;
type T_InboxReplyInput = sdk.InboxReplyInput;
type T_InboxStatus = sdk.InboxStatus;
type T_InboxUpdateInput = sdk.InboxUpdateInput;
type T_MailboxCreated = sdk.MailboxCreated;
type T_MailMask = sdk.MailMask;
type T_MailMaskConfig = sdk.MailMaskConfig;
type T_MailMaskError = sdk.MailMaskError;
type T_Order = sdk.Order;
type T_OrdersPage = sdk.OrdersPage;
type T_ReferralStats = sdk.ReferralStats;
type T_RenewalLink = sdk.RenewalLink;
type T_Rule = sdk.Rule;
type T_RuleAction = sdk.RuleAction;
type T_RuleField = sdk.RuleField;
type T_RuleMatch = sdk.RuleMatch;
type T_SendEmailInput = sdk.SendEmailInput;
type T_SendOptions = sdk.SendOptions;
type T_SmtpCredential = sdk.SmtpCredential;
type T_SmtpCredentialCreated = sdk.SmtpCredentialCreated;
type T_Suppression = sdk.Suppression;
type T_TldPrice = sdk.TldPrice;
type T_TransferCheck = sdk.TransferCheck;
type T_TransferDnsInventory = sdk.TransferDnsInventory;
type T_TransferRequirement = sdk.TransferRequirement;
type T_UpdateAddressInput = sdk.UpdateAddressInput;
type T_UpdateAliasInput = sdk.UpdateAliasInput;
type T_UpdateRuleInput = sdk.UpdateRuleInput;
type T_UpdateWebhookInput = sdk.UpdateWebhookInput;
type T_UploadAttachmentInput = sdk.UploadAttachmentInput;
type T_UploadedAttachment = sdk.UploadedAttachment;
type T_UploadedEmailImage = sdk.UploadedEmailImage;
type T_Webhook = sdk.Webhook;
type T_WebhookCreated = sdk.WebhookCreated;
type T_WebhookDelivery = sdk.WebhookDelivery;
type T_WebhookEvent = sdk.WebhookEvent;
type T_WebhookPayload = sdk.WebhookPayload;
type T_WebhookSignatureHeaders = sdk.WebhookSignatureHeaders;

/* --- Valores publicados (3): los bundles ESM y CJS deben exponerlos --- */
const V_MailMask = sdk.MailMask;
const V_MailMaskError = sdk.MailMaskError;
const V_verifyWebhookSignature = sdk.verifyWebhookSignature;

// Los alias se usan para que el compilador no los descarte.
export type PublicTypes = readonly [
  T_AccountExport,
  T_AccountMe,
  T_AccountMeDomainUsage,
  T_AccountProfile,
  T_Addon,
  T_AddonsResponse,
  T_Address,
  T_AddressCreated,
  T_Alias,
  T_AliasCreated,
  T_ApiKey,
  T_AttachmentRef,
  T_BillingStatus,
  T_BulkJob,
  T_BulkJobCreated,
  T_BulkSendInput,
  T_CannedReply,
  T_CheckoutLink,
  T_CreateAddressInput,
  T_CreateAliasInput,
  T_CreateRuleInput,
  T_CreateWebhookInput,
  T_DnsChangeResult,
  T_DnsDelegation,
  T_DnsImportResult,
  T_DnsListResponse,
  T_DnsPreset,
  T_DnsRecord,
  T_DnsRecordType,
  T_DnsRRSet,
  T_DnsRRSetAnotado,
  T_DnsSetup,
  T_DnsSetupRecord,
  T_DnsZoneCreated,
  T_DnsZoneState,
  T_Domain,
  T_DomainCreated,
  T_DomainInvite,
  T_DomainMember,
  T_DomainRegistration,
  T_DomainRegistrationCreated,
  T_DomainSearchResult,
  T_DomainVerification,
  T_EmailLog,
  T_InboxAttachment,
  T_InboxComposeInput,
  T_InboxConversation,
  T_InboxConversationDetail,
  T_InboxListOptions,
  T_InboxMessage,
  T_InboxNote,
  T_InboxPage,
  T_InboxReplyInput,
  T_InboxStatus,
  T_InboxUpdateInput,
  T_MailboxCreated,
  T_MailMask,
  T_MailMaskConfig,
  T_MailMaskError,
  T_Order,
  T_OrdersPage,
  T_ReferralStats,
  T_RenewalLink,
  T_Rule,
  T_RuleAction,
  T_RuleField,
  T_RuleMatch,
  T_SendEmailInput,
  T_SendOptions,
  T_SmtpCredential,
  T_SmtpCredentialCreated,
  T_Suppression,
  T_TldPrice,
  T_TransferCheck,
  T_TransferDnsInventory,
  T_TransferRequirement,
  T_UpdateAddressInput,
  T_UpdateAliasInput,
  T_UpdateRuleInput,
  T_UpdateWebhookInput,
  T_UploadAttachmentInput,
  T_UploadedAttachment,
  T_UploadedEmailImage,
  T_Webhook,
  T_WebhookCreated,
  T_WebhookDelivery,
  T_WebhookEvent,
  T_WebhookPayload,
  T_WebhookSignatureHeaders,
];
export const publicValues: readonly unknown[] = [V_MailMask, V_MailMaskError, V_verifyWebhookSignature];
