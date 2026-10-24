# API compatibility policy

Tessera serves its API under two prefixes.

- `/api/v1/...` is the stable, customer-facing API. Every `/api/...` route is also served here, with the same session or token authentication, permissions and scopes, CSRF and rate limits, and audit event (the event names the route's `/api/...` template). A v1 answer carries `Tessera-API-Version: 1`.
- `/api/...` is the same routes without a version. The admin UI uses it and it can change with the UI. Integrations should use `/api/v1`.

`/scim/v2`, `/t/{tenant}/oauth/...` and `/.well-known/...` follow their own standards and have their own versioning; they are not aliased under `/api/v1`.

## Within v1

Allowed without notice (additive):

- new routes, new optional request fields and query parameters;
- new fields in responses (clients must ignore unknown fields);
- new values in documented open sets such as error codes, and new scopes or permissions;
- bug fixes that make behaviour match this document and the OpenAPI document.

Not allowed in v1: removing or renaming a route, field, parameter or scope; changing a field's type or meaning; making an optional input required; tightening validation of previously accepted input; changing a success status code. These need a new major version (`/api/v2`).

## Deprecation and removal

A route or field to be removed in v1 is first deprecated, and stays working for **at least 6 months** after the announcement. While deprecated, every answer of the route under `/api/v1` carries:

- `Deprecation: @<unix seconds>` (RFC 9745): when it was deprecated;
- `Sunset: <HTTP date>` (RFC 8594): when it stops working;
- `Link: <url>; rel="deprecation"` when a migration guide exists.

The server refuses to start with a deprecation whose Sunset is less than 6 months (180 days) after its Deprecation date (`api.Config.Deprecations`). The OpenAPI document (`GET /api/openapi.json`) is the reference for what each route needs.

## Errors and lists on v1

These apply to `/api/v1` only; the unversioned `/api` paths keep their older shapes for the UI.

**One error envelope.** Every answer with status 400 or more is
`{"error": {"code": "...", "message": "...", "field": "...", "details": {...}}}`. `code` is stable and machine readable
(`forbidden`, `step_up_required`, `rate_limited`, `validation_error`, `invalid_cursor`, ...; a status with no route code gets
`not_found`, `conflict`, `internal_error`, ...). `message` is for people and may change. `field` names the offending input when
known. `details` carries extra fields of the error, such as the step-up challenge or the list of validation errors.

**Lists.** A list answers `{"items": [...], "next_cursor": "..." | null}`. Query `limit` (1 to 500, default 100) and `cursor`
(the `next_cursor` of the previous page; absent or null on the last page). A cursor is bound to its route and its other
query parameters; used with different ones it is `400 invalid_cursor`. `filter`, `sort` and other parameters are the route's
own, where it has them. Routes that already page natively with `limit` and `offset` (the groups lists) keep their body and gain
`next_cursor`. Limits of the first release: for most routes the server cuts the full answer, so a page costs as much as the
list; `GET /api/v1/audit` is cut at the source and pages up to the audit limit.
