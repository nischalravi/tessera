package awstest

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
)

// The fixed names of Estate.
const (
	EstateProd   = "111111111111" // the account that holds the data
	EstateDev    = "222222222222"
	EstateOrg    = "o-estate"
	EstateRoot   = "r-estate"
	EstateOUProd = "ou-prod"

	EstateAlice    = "arn:aws:iam::111111111111:user/alice"
	EstateBob      = "arn:aws:iam::111111111111:user/bob"
	EstateEngineer = "arn:aws:iam::111111111111:role/DataEngineer"
	EstateDevUser  = "arn:aws:iam::222222222222:user/dev"
	EstateGroup    = "arn:aws:iam::111111111111:group/eng"
	EstateBucket   = "arn:aws:s3:::prod-pii"
	EstateObjects  = "arn:aws:s3:::prod-pii/*"
	EstateKey      = "arn:aws:kms:us-east-1:111111111111:key/k1"
	EstateS3Read   = "arn:aws:iam::111111111111:policy/S3Read"
	EstateFullSCP  = "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"
	EstateFullRCP  = "arn:aws:organizations::aws:policy/resource_control_policy/p-RCPFullAWSAccess"
)

// EstateTime is the time Estate says it was taken.
var EstateTime = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// Estate is a small readable estate for the integration tests of the MVP: two
// accounts in an organization, a bucket with personal data, a KMS key, and who
// can reach them.
//
//   - alice (user, prod) holds the managed policy S3Read (s3:GetObject on
//     prod-pii objects) and may assume DataEngineer.
//   - bob (user, prod) is in group eng, whose inline policy lets its members
//     list the bucket.
//   - DataEngineer (role, prod) may decrypt with the key and be assumed by
//     principals of the prod account (its trust policy names the account root).
//   - dev (user, dev account) holds no policy. The dev account is the
//     organization's management account, which no SCP affects.
//   - the organization attaches an allow-all SCP and RCP at every level.
//
// A policy pull request against it is the exit-criterion-2 test of design §2:
// widen S3Read, or give the bucket a policy, and the diff names who gains what.
func Estate() (*model.Snapshot, error) {
	b := snapshot.NewBuilder()
	b.SetTakenAt(EstateTime)
	doc := func(kind model.PolicyKind, src, raw string) string {
		return b.AddPolicy(policy.Options{Kind: kind, SourceARN: src, FetchedAt: EstateTime}, []byte(raw)).ID
	}
	const v = `"Version":"2012-10-17"`
	s3read := doc(model.PolicyIdentity, EstateS3Read,
		`{`+v+`,"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"`+EstateObjects+`"}]}`)
	assume := doc(model.PolicyIdentity, EstateAlice+"#inline/assume",
		`{`+v+`,"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"`+EstateEngineer+`"}]}`)
	groupList := doc(model.PolicyIdentity, EstateGroup+"#inline/list",
		`{`+v+`,"Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"`+EstateBucket+`"}]}`)
	decrypt := doc(model.PolicyIdentity, EstateEngineer+"#inline/decrypt",
		`{`+v+`,"Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":"`+EstateKey+`"}]}`)
	trust := doc(model.PolicyTrust, EstateEngineer+"#trust",
		`{`+v+`,"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}]}`)
	keyPolicy := doc(model.PolicyKMSKey, EstateKey+"#policy",
		`{`+v+`,"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"kms:*","Resource":"*"}]}`)
	scp := doc(model.PolicySCP, EstateFullSCP,
		`{`+v+`,"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)

	rcp := doc(model.PolicyRCP, EstateFullRCP,
		`{`+v+`,"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`)

	// AWS attaches its allow-all SCP and RCP at every level, since an allow is
	// needed at each one.
	node := func(id string, kind model.OrgNodeKind, parent, name string) *model.OrgNode {
		b.Attach(model.PolicyAttachment{PolicyID: scp, TargetARN: id, AttachmentType: model.AttachSCP})
		b.Attach(model.PolicyAttachment{PolicyID: rcp, TargetARN: id, AttachmentType: model.AttachRCP})
		return &model.OrgNode{ID: id, Kind: kind, ParentID: parent, Name: name, SCPIDs: []string{scp}, RCPIDs: []string{rcp}}
	}
	b.SetOrg(&model.Organization{OrgID: EstateOrg, ManagementAccountID: EstateDev, SCPEnabled: true, RCPEnabled: true,
		Nodes: map[string]*model.OrgNode{
			EstateRoot:   node(EstateRoot, model.OrgRoot, "", "Root"),
			EstateOUProd: node(EstateOUProd, model.OrgOU, EstateRoot, "prod"),
			EstateProd:   node(EstateProd, model.OrgAccount, EstateOUProd, "prod"),
			EstateDev:    node(EstateDev, model.OrgAccount, EstateRoot, "dev"),
		}})

	attach := func(p *model.Principal, id string, typ model.AttachmentType, via ...string) {
		p.IdentityPolicyIDs = append(p.IdentityPolicyIDs, id)
		b.Attach(model.PolicyAttachment{PolicyID: id, TargetARN: p.ARN, Via: via, AttachmentType: typ})
	}
	user := func(arn, acct, uid string, groups ...string) *model.Principal {
		p := &model.Principal{ARN: arn, Kind: model.IAMUser, AccountID: acct, UniqueID: uid, Path: "/", GroupARNs: groups}
		b.AddPrincipal(p)
		b.AddResource(&model.Resource{ARN: arn, Type: "user", AccountID: acct})
		return p
	}
	alice := user(EstateAlice, EstateProd, "AIDAALICE")
	attach(alice, s3read, model.AttachManaged)
	attach(alice, assume, model.AttachInline)
	bob := user(EstateBob, EstateProd, "AIDABOB", EstateGroup)
	attach(bob, groupList, model.AttachInline, "group/eng")
	user(EstateDevUser, EstateDev, "AIDADEV")

	role := &model.Principal{ARN: EstateEngineer, Kind: model.IAMRole, AccountID: EstateProd, UniqueID: "AROAENG", Path: "/"}
	attach(role, decrypt, model.AttachInline)
	b.AddPrincipal(role)
	b.AddResource(&model.Resource{ARN: EstateEngineer, Type: "role", AccountID: EstateProd})
	b.AddResourcePolicy(model.ResourcePolicy{ResourceARN: EstateEngineer, Kind: model.PolicyTrust, PolicyID: trust, RequiresExplicitAllow: true})
	b.Attach(model.PolicyAttachment{PolicyID: trust, TargetARN: EstateEngineer, AttachmentType: model.AttachTrust})

	b.AddResource(&model.Resource{ARN: EstateBucket, Type: "bucket", AccountID: EstateProd, Region: "us-east-1"})
	b.AddS3Bucket(&model.S3BucketState{BucketARN: EstateBucket, OwnerAccount: EstateProd, ObjectOwnership: "BucketOwnerEnforced"})
	b.SetCanonicalID("canonical-prod", EstateProd)
	b.AddResource(&model.Resource{ARN: EstateKey, Type: "key", AccountID: EstateProd, Region: "us-east-1"})
	b.AddResourcePolicy(model.ResourcePolicy{ResourceARN: EstateKey, Kind: model.PolicyKMSKey, PolicyID: keyPolicy, RequiresExplicitAllow: true})
	b.Attach(model.PolicyAttachment{PolicyID: keyPolicy, TargetARN: EstateKey, AttachmentType: model.AttachResource})
	return b.Build()
}
