# AWS catalog data

Inputs and outputs of `internal/aws/catalog` (design §10). Commands are in `mvp/README.md`
("AWS action catalog").

```text
iam-dataset.lock        reviewed pin of the iam-dataset input: repo, full commit SHA, path, SHA-256
overlays/*.yaml         curated data, reviewed by iam-authz-expert (RCP list, KMS cross-account ops,
                        global keys, S3 ACL map, rbp_rules, opt-in regions, S3 public fixed keys)
snapshots/<date>/       written by `tessera catalog refresh`, immutable:
  MANIFEST.json           SHA-256 of every file below
  index.json              the Service Reference index as fetched
  services/<svc>.json     Service Reference files, verbatim
  rcp_services.json       RCP service prefixes scraped from the Organizations guide that day
  iam-dataset-extract.json  access level and dependent actions taken from the pinned iam-dataset file
compiled/<version>.json.gz  written by `tessera catalog compile`; version = <snapshot date>-<16 hex>
                        of the SHA-256 of the canonical JSON (RFC 8785)
THIRD_PARTY_NOTICES     licences of third-party data
```

No snapshot or compiled artifact is committed yet: the first `refresh` and `compile` produce them
(a snapshot is about 19 MB of JSON; the compiled artifact is about 260 KB).

Trust model: the Service Reference publishes no digest, so the fetch is pinned by host (only the
index host, over https through `safehttp`; per-service URLs are built from a validated service
prefix, never taken from the index), size caps and strict parsing; the manifest then detects any
later change to the stored files. The iam-dataset file is pinned by commit and digest and refused
on mismatch. Bump the pin in `iam-dataset.lock` in a reviewed PR.

Changing an overlay changes the catalog version. Changes to `overlays/` and to the RCP list need
iam-authz-expert review. The RCP overlay is never edited automatically: `compile` reports where the
live page and the overlay differ.
