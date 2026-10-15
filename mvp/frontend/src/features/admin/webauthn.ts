/**
 * WebAuthn in the browser, for break-glass keys (design §9.6, §15.4). The API speaks go-webauthn's
 * JSON, in which every binary value (challenge, user id, credential ids) is base64url; the browser
 * API wants bytes, and the server wants base64url back. Nothing here talks to the API: api.ts does.
 * The conversions are plain functions so `npm test` can check them without a browser.
 */
import type { WebAuthnOptionsJSON } from "../../api";

/** base64url (no padding) of bytes. */
export function bytesToB64u(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The bytes of a base64url string (padding optional). Throws on anything else. */
export function b64uToBytes(input: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(input)) throw new Error("not base64url");
  const s = input.replace(/=+$/, "");
  const std = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(std);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

type Descriptor = { id: string; type: "public-key"; transports?: string[] };

const descriptors = (list: Descriptor[] | undefined): PublicKeyCredentialDescriptor[] =>
  (list ?? []).map((d) => ({ ...d, id: b64uToBytes(d.id), transports: d.transports as AuthenticatorTransport[] | undefined }));

/** The creation options of POST …/registration/options as navigator.credentials.create wants them. */
export function creationOptions(j: WebAuthnOptionsJSON): PublicKeyCredentialCreationOptions {
  const o = j.publicKey;
  return { ...o, challenge: b64uToBytes(o.challenge), user: { ...o.user, id: b64uToBytes(o.user.id) },
    excludeCredentials: descriptors(o.excludeCredentials) } as unknown as PublicKeyCredentialCreationOptions;
}

/** The request options of POST /api/auth/break-glass/options as navigator.credentials.get wants them. */
export function requestOptions(j: WebAuthnOptionsJSON): PublicKeyCredentialRequestOptions {
  const o = j.publicKey;
  return { ...o, challenge: b64uToBytes(o.challenge), allowCredentials: descriptors(o.allowCredentials) } as unknown as PublicKeyCredentialRequestOptions;
}

/** The PublicKeyCredential JSON of a registration, as the server's verify call expects it. */
export function attestationJSON(c: PublicKeyCredential): Record<string, unknown> {
  const r = c.response as AuthenticatorAttestationResponse;
  return {
    id: c.id, rawId: bytesToB64u(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment ?? undefined,
    response: { clientDataJSON: bytesToB64u(r.clientDataJSON), attestationObject: bytesToB64u(r.attestationObject),
      transports: typeof r.getTransports === "function" ? r.getTransports() : [] },
    clientExtensionResults: c.getClientExtensionResults(),
  };
}

/** The PublicKeyCredential JSON of an assertion, as the server's sign-in call expects it. */
export function assertionJSON(c: PublicKeyCredential): Record<string, unknown> {
  const r = c.response as AuthenticatorAssertionResponse;
  return {
    id: c.id, rawId: bytesToB64u(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment ?? undefined,
    response: { clientDataJSON: bytesToB64u(r.clientDataJSON), authenticatorData: bytesToB64u(r.authenticatorData),
      signature: bytesToB64u(r.signature), userHandle: r.userHandle && r.userHandle.byteLength > 0 ? bytesToB64u(r.userHandle) : undefined },
    clientExtensionResults: c.getClientExtensionResults(),
  };
}

/** Whether this browser can do WebAuthn at all. */
export const webauthnSupported = () => typeof window !== "undefined" && typeof window.PublicKeyCredential === "function";

/** What to tell the user when the browser's own prompt ended without a credential. */
export function ceremonyMessage(e: unknown): string {
  const name = (e as { name?: string })?.name;
  if (name === "NotAllowedError") return "The security key was not used: the prompt was cancelled or timed out. Try again.";
  if (name === "InvalidStateError") return "This security key is already registered for this user.";
  if (name === "NotSupportedError") return "This browser or key does not support the required settings (a hardware key that verifies you with a PIN or fingerprint).";
  if (name === "SecurityError") return "The browser refused to use the key on this address. Break-glass keys work only on the organization's own Tessera address.";
  return String((e as Error)?.message ?? e);
}

/** Ask the key to create a credential for the options; resolves to the JSON the server verifies. */
export async function registerKey(options: WebAuthnOptionsJSON): Promise<Record<string, unknown>> {
  const c = await navigator.credentials.create({ publicKey: creationOptions(options) });
  if (!(c instanceof PublicKeyCredential)) throw new Error("The browser returned no credential.");
  return attestationJSON(c);
}

/** Ask the key to sign the challenge; resolves to the JSON the server verifies. */
export async function signWithKey(options: WebAuthnOptionsJSON): Promise<Record<string, unknown>> {
  const c = await navigator.credentials.get({ publicKey: requestOptions(options) });
  if (!(c instanceof PublicKeyCredential)) throw new Error("The browser returned no credential.");
  return assertionJSON(c);
}
