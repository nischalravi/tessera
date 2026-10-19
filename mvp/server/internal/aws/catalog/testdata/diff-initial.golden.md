## catalog: 2026-10-01 (+11 actions, +3 RCP services)

Catalog version `<v1>` (from `(none)`)

### Services added (3)

- `kms`
- `s3`
- `sqs`

### Actions added (11)

- `kms:CreateGrant`
- `kms:Decrypt`
- `kms:Encrypt`
- `s3:GetObject`
- `s3:GetObjectAcl`
- `s3:ListAllMyBuckets`
- `s3:ListBucket`
- `s3:PutBucketPolicy`
- `s3:PutObject`
- `s3:PutObjectTagging`
- `sqs:SendMessage`

### Condition keys added (58)

- `aws:AssumedRoot`
- `aws:CalledVia`
- `aws:CalledViaFirst`
- `aws:CalledViaLast`
- `aws:CurrentTime`
- `aws:Ec2InstanceSourcePrivateIPv4`
- `aws:Ec2InstanceSourceVpc`
- `aws:EpochTime`
- `aws:FederatedProvider`
- `aws:MultiFactorAuthAge`
- `aws:MultiFactorAuthPresent`
- `aws:PrincipalAccount`
- `aws:PrincipalArn`
- `aws:PrincipalIsAWSService`
- `aws:PrincipalOrgID`
- `aws:PrincipalOrgPaths`
- `aws:PrincipalServiceName`
- `aws:PrincipalServiceNamesList`
- `aws:PrincipalTag/${TagKey}`
- `aws:PrincipalType`
- `aws:Referer`
- `aws:RequestTag/${TagKey}`
- `aws:RequestedRegion`
- `aws:ResourceAccount`
- `aws:ResourceOrgID`
- `aws:ResourceOrgPaths`
- `aws:ResourceTag/${TagKey}`
- `aws:SecureTransport`
- `aws:SourceAccount`
- `aws:SourceArn`
- `aws:SourceIdentity`
- `aws:SourceIp`
- `aws:SourceOrgID`
- `aws:SourceOrgPaths`
- `aws:SourceOwner`
- `aws:SourceVpc`
- `aws:SourceVpce`
- `aws:TagKeys`
- `aws:TokenIssueTime`
- `aws:UserAgent`
- `aws:ViaAWSService`
- `aws:VpcSourceIp`
- `aws:VpceAccount`
- `aws:VpceOrgID`
- `aws:VpceOrgPaths`
- `aws:userid`
- `aws:username`
- `kms:EncryptionContext:${EncryptionContextKey}`
- `kms:EncryptionContextKeys`
- `kms:GrantOperations`
- `kms:GranteePrincipal`
- `s3:RequestObjectTag/<key>`
- `s3:ResourceAccount`
- `s3:TlsVersion`
- `s3:delimiter`
- `s3:max-keys`
- `s3:prefix`
- `s3:x-amz-acl`

### RCP services added to the overlay (3)

- `kms`
- `s3`
- `sqs`

