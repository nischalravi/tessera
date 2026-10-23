// Client-side checks for the new IdP connection form (SAML fields), and the mapping of server
// validation errors onto form fields. The server still validates everything.

export type FieldErrors = Partial<Record<"entity" | "sso" | "cert", string>>;

/** Catches the SAML mistakes the server would refuse, before a round trip. The server still validates everything. */
export function checkSAMLFields(sso: string, cert: string): FieldErrors {
  const out: FieldErrors = {};
  try {
    const u = new URL(sso.trim());
    if (u.protocol !== "https:" && u.protocol !== "http:") out.sso = "Enter the IdP's sign-in URL, starting with https://.";
  } catch {
    out.sso = "Enter the IdP's sign-in URL, starting with https://.";
  }
  const c = cert.trim();
  const pem = /-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/.test(c);
  const der = /^[A-Za-z0-9+/=\s]{200,}$/.test(c);
  if (!pem && !der) out.cert = "This isn't a certificate. Paste the PEM text, from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE-----.";
  return out;
}

/** Maps a validation error from the server to the field it is about, in plain words. */
export function serverFieldError(msg: string): { key: keyof FieldErrors; text: string } | null {
  if (msg.includes("idp_signing_certs")) return { key: "cert", text: "Tessera couldn't read this certificate. Check you pasted the whole PEM block, including the BEGIN and END lines, and that it isn't a private key." };
  if (msg.includes("idp_sso_url")) return { key: "sso", text: msg.includes("https") ? "The sign-in URL must use https." : "Enter the IdP's full sign-in URL." };
  if (msg.includes("idp_entity_id")) return { key: "entity", text: "Enter the IdP's entity ID exactly as it appears in its metadata." };
  return null;
}
