# Runbook: emergency revocation of a signing key

Use this when a tenant's active signing key (`access_token` or `idp_client_auth`) or the platform
audit-checkpoint key may be compromised. Design: `docs/design/phase-0-platform-security.md` §10.2,
§10.4, §10.6 (threat E6).

## What revocation does

- `keys.RevokeKey` marks the key `revoked` and, if it was the active key, activates the tenant's
  `next` key at once and mints a new `next` key. A revoked key is never published again and never
  verifies a token in Tessera.
- Revoking a key twice returns `ErrNotFound` and changes nothing.
- The platform key: `store.SystemTx.RevokePlatformKey` takes it out of `GET /api/audit/keys`.
  Checkpoints it signed no longer verify (`tessera audit verify` exit code 4) until they are
  re-signed under the new key; record the revocation in the incident log so the failure is expected.

There is no admin CLI command for revocation yet. Until it lands, an operator runs it from a
maintenance build against the database, inside the tenant's transaction, and records it in the
incident log.

## The JWKS cache trade-off

The tenant JWKS (`/t/{slug}/.well-known/jwks.json`) is served with `Cache-Control: max-age=300`.
The cache is what lets relying parties survive a Tessera outage and keeps key rotation smooth (a
`next` key is published at least 7 days before it signs anything, so every cache already holds
it). In an emergency the same cache works against you:

1. **The revoked key keeps verifying at relying parties for up to the cache lifetime.** A relying
   party that fetched the JWKS just before the revocation accepts tokens signed with the revoked key
   for up to 300 s. Some libraries ignore `Cache-Control` and keep a JWKS much longer (hours, or
   until restart). Tessera cannot shorten a cache it does not own.
2. **Tokens already issued stay valid until they expire.** Access tokens live at most 900 s
   (`TESSERA_AT_TTL_SECONDS`, default 600). The worst case for an attacker holding the key is
   therefore about one cache lifetime plus one token lifetime at relying parties that do not
   re-check, and zero inside Tessera itself.
3. **The newly active key is normally already cached.** It was the `next` key, so relying parties
   verify the new tokens without a refetch. If the `next` key was revoked too (or was created
   minutes ago), relying parties with a stale cache see an unknown `kid`; well-behaved libraries
   refetch the JWKS on an unknown `kid`, others fail until their cache expires.

We keep `max-age=300` rather than a shorter value: a shorter cache multiplies JWKS traffic and
makes every relying party depend on Tessera being up, to shave minutes off a rare event that the
steps below cover.

## Steps

1. Revoke the key (above). Confirm the JWKS no longer lists its `kid` and lists the new active key.
2. Revoke what the key could have minted: sessions and refresh tokens of the tenant (or of the
   affected clients), so no new access token comes from a stolen grant.
3. Tell the tenant's relying-party owners to flush their JWKS cache (or restart the service) if
   they cannot wait 300 s, and to check that their library refetches on an unknown `kid`.
4. Watch the logs for `keys.bad_public_jwk` (level ERROR, `alert=true`): a stored public key that
   fails validation is left out of the JWKS instead of failing the whole set, and must be
   investigated as possible tampering.
5. After the token lifetime plus the cache lifetime (about 20 minutes), the revoked key is inert
   everywhere that honours the cache headers. Record the times in the incident log.
