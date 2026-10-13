/**
 * The claim session's key binding (threat T20). The page makes an ECDSA P-256 key with WebCrypto,
 * non-extractable, so the private key can be used but never read back, even by a script on the page.
 * Only the public key goes to the API, with `start`. Every later request carries
 *
 *   X-Claim-Proof: <unix seconds>.<base64url(r||s)>
 *
 * a signature over "tessera-claim-proof-v1\n" + METHOD + "\n" + PATH + "\n" + seconds + "\n" + nonce
 * (the nonce is the session's, empty for `start`). WebCrypto's ECDSA output is already r||s, which
 * is the form the server verifies. Keep the message in step with internal/guests/claim/proof.go.
 */

export const PROOF_DOMAIN = "tessera-claim-proof-v1";

export const proofMessage = (method: string, path: string, seconds: number, nonce: string) =>
  `${PROOF_DOMAIN}\n${method}\n${path}\n${seconds}\n${nonce}`;

export function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const ALGORITHM = { name: "ECDSA", namedCurve: "P-256" } as const;

/** A new non-extractable signing key (the public half can still be exported). */
export const generateKey = (): Promise<CryptoKeyPair> =>
  crypto.subtle.generateKey(ALGORITHM, false, ["sign", "verify"]) as Promise<CryptoKeyPair>;

/** The public key as a JWK: kty, crv, x and y only. */
export async function publicJwk(pair: CryptoKeyPair): Promise<JsonWebKey> {
  const j = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { kty: j.kty, crv: j.crv, x: j.x, y: j.y };
}

/** The X-Claim-Proof value for one request. */
export async function makeProof(key: CryptoKey, method: string, path: string, nonce: string, nowMs: number = Date.now()): Promise<string> {
  const seconds = Math.floor(nowMs / 1000);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(proofMessage(method, path, seconds, nonce)));
  return `${seconds}.${b64url(sig)}`;
}

/** A ClaimSigner over a key pair. */
export const signerFor = (pair: CryptoKeyPair) => ({
  sign: (method: string, path: string, nonce: string) => makeProof(pair.privateKey, method, path, nonce),
});
