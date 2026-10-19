## catalog: 2026-10-08 (+3 actions, -3 actions, +1 RCP service)

Catalog version `<v2>` (from `<v1>`)

### Services added (1)

- `sns`

### Actions added (3)

- `s3:DeleteObject`
- `s3:GetObjectAttributes`
- `sns:Publish`

### Actions removed (3)

- `kms:Encrypt`
- `s3:ListAllMyBuckets`
- `s3:PutObjectTagging`

### Access level changes (1)

- `kms:CreateGrant: permissions_management -> write`

### Condition keys added (1)

- `kms:ViaService`

### RCP page lists these services, the overlay does not (needs iam-authz-expert review) (1)

- `sns`

