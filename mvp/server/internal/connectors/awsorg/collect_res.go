package awsorg

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// addResourcePolicy records a resource and, when it has a policy, parses and
// attaches it. A policy that does not parse is a finding over the resource.
func (b *builder) addResourcePolicy(arn, typ, account, region string, kind model.PolicyKind, text string) {
	b.snap.Resources[arn] = &model.Resource{ARN: arn, Type: typ, AccountID: account, Region: region}
	if text == "" {
		return
	}
	ref := b.parseDoc(kind, arn+"#policy", "", text, false, Scope{Type: ScopeResources, Targets: []string{arn}})
	if !ref.ok() {
		return
	}
	b.snap.ResourcePolicies[arn] = append(b.snap.ResourcePolicies[arn],
		model.ResourcePolicy{ResourceARN: arn, Kind: kind, PolicyID: ref.id, RequiresExplicitAllow: kind == model.PolicyKMSKey})
	b.snap.Attachments = append(b.snap.Attachments, model.PolicyAttachment{PolicyID: ref.id, TargetARN: arn, AttachmentType: model.AttachResource})
}

// resourceGap records a resource whose policy could not be read.
func (b *builder) resourceGap(arn, op string, err error) {
	b.gap(arn, errCode(err), op+": "+errDetail(err), Scope{Type: ScopeResources, Targets: []string{arn}})
}

// listGap records a list call that failed: every resource under prefix is unknown.
func (b *builder) listGap(source, op string, err error, prefix string) {
	b.gap(source, errCode(err), op+": "+errDetail(err), Scope{Type: ScopeResourcePrefix, Targets: []string{prefix}})
}

// ---------------------------------------------------------------- S3

func (c *Collector) collectS3(ctx context.Context, b *builder, s session, account string) {
	region := c.Config.Regions[0]
	acctScope := Scope{Type: ScopeResourceAccounts, Targets: []string{account}}

	bpaAccount, err := s.getAccountPublicAccessBlock(ctx, account, region)
	if err != nil {
		b.gap(account, errCode(err), "s3control GetPublicAccessBlock: "+errDetail(err), acctScope)
	}

	buckets, owner, err := s.listBuckets(ctx, region)
	if err != nil {
		b.gap(account, errCode(err), "s3 ListBuckets: "+errDetail(err), acctScope)
	} else if owner != "" {
		b.snap.CanonicalIDs[owner] = account
	}
	for _, bk := range buckets {
		bregion := bk.Region
		if bregion == "" {
			bregion = region
		}
		arn := "arn:aws:s3:::" + bk.Name
		if !bucketRE.MatchString(bk.Name) || !regionRE.MatchString(bregion) {
			b.gap(arn, "InvalidBucket", "bucket name or region is not valid", Scope{Type: ScopeResources, Targets: []string{arn}})
			continue
		}
		st := &model.S3BucketState{BucketARN: arn, OwnerAccount: account, BPAAccount: model.BPA(bpaAccount)}
		b.snap.S3[arn] = st

		text, err := s.getBucketPolicy(ctx, bk.Name, bregion)
		if err != nil {
			b.resourceGap(arn, "s3 GetBucketPolicy", err)
		}
		b.addResourcePolicy(arn, "bucket", account, bregion, model.PolicyResource, text)

		if acl, err := s.getBucketACL(ctx, bk.Name, bregion); err != nil {
			b.resourceGap(arn, "s3 GetBucketAcl", err)
		} else {
			for _, g := range acl.Grants {
				ag := model.ACLGrant{GranteeType: g.Grantee.Type, Permission: g.Permission}
				switch g.Grantee.Type {
				case "CanonicalUser":
					ag.Grantee = g.Grantee.ID
				case "Group":
					ag.Grantee = g.Grantee.URI
				default:
					ag.Grantee = g.Grantee.Email
				}
				st.BucketACL = append(st.BucketACL, ag)
			}
		}
		if own, err := s.getOwnershipControls(ctx, bk.Name, bregion); err != nil {
			b.resourceGap(arn, "s3 GetBucketOwnershipControls", err)
		} else {
			st.ObjectOwnership = own
		}
		if bpa, err := s.getBucketPublicAccessBlock(ctx, bk.Name, bregion); err != nil {
			b.resourceGap(arn, "s3 GetBucketPublicAccessBlock", err)
		} else {
			st.BPABucket = model.BPA(bpa)
		}
	}

	for _, r := range c.Config.Regions {
		prefix := "arn:aws:s3:" + r + ":" + account + ":accesspoint/"
		aps, err := s.listAccessPoints(ctx, account, r)
		if err != nil {
			b.listGap(account, "s3control ListAccessPoints in "+r, err, prefix)
			continue
		}
		for _, ap := range aps {
			arn := ap.ARN
			if arn == "" {
				arn = prefix + ap.Name
			}
			text, err := s.getAccessPointPolicy(ctx, account, r, ap.Name)
			if err != nil {
				b.resourceGap(arn, "s3control GetAccessPointPolicy", err)
			}
			b.addResourcePolicy(arn, "accesspoint", account, r, model.PolicyS3AccessPoint, text)
		}
	}
}

// ---------------------------------------------------------------- regional services

func (c *Collector) collectRegion(ctx context.Context, b *builder, s session, account, region string) {
	pfx := func(service string) string { return "arn:aws:" + service + ":" + region + ":" + account + ":" }

	// KMS
	if keys, err := s.listKeys(ctx, region); err != nil {
		b.listGap(account, "kms ListKeys in "+region, err, pfx("kms"))
	} else {
		for _, k := range keys {
			arn := k.ARN
			if described, err := s.describeKey(ctx, region, k.ID); err != nil {
				b.resourceGap(arn, "kms DescribeKey", err)
			} else if described != "" {
				arn = described
			}
			text, err := s.getKeyPolicy(ctx, region, k.ID)
			if err != nil {
				b.resourceGap(arn, "kms GetKeyPolicy", err)
			}
			b.addResourcePolicy(arn, "key", account, region, model.PolicyKMSKey, text)
			if grants, err := s.listGrants(ctx, region, k.ID); err != nil {
				b.resourceGap(arn, "kms ListGrants", err)
			} else {
				for _, g := range grants {
					b.snap.KMSGrants[arn] = append(b.snap.KMSGrants[arn], kmsGrant(arn, g))
				}
			}
		}
	}

	// SQS
	if urls, err := s.listQueueURLs(ctx, region); err != nil {
		b.listGap(account, "sqs ListQueues in "+region, err, pfx("sqs"))
	} else {
		for _, u := range urls {
			arn, text, err := s.queuePolicy(ctx, region, u)
			if err != nil {
				b.listGap(u, "sqs GetQueueAttributes", err, pfx("sqs")+u[strings.LastIndex(u, "/")+1:])
				continue
			}
			if arn == "" {
				b.listGap(u, "sqs GetQueueAttributes", errNoARN, pfx("sqs")+u[strings.LastIndex(u, "/")+1:])
				continue
			}
			b.addResourcePolicy(arn, "queue", account, region, model.PolicyResource, text)
		}
	}

	// SNS
	if topics, err := s.listTopics(ctx, region); err != nil {
		b.listGap(account, "sns ListTopics in "+region, err, pfx("sns"))
	} else {
		for _, t := range topics {
			text, err := s.topicPolicy(ctx, region, t)
			if err != nil {
				b.resourceGap(t, "sns GetTopicAttributes", err)
			}
			b.addResourcePolicy(t, "topic", account, region, model.PolicyResource, text)
		}
	}

	// Secrets Manager
	if secrets, err := s.listSecretARNs(ctx, region); err != nil {
		b.listGap(account, "secretsmanager ListSecrets in "+region, err, pfx("secretsmanager"))
	} else {
		for _, sec := range secrets {
			text, err := s.secretPolicy(ctx, region, sec)
			if err != nil {
				b.resourceGap(sec, "secretsmanager GetResourcePolicy", err)
			}
			b.addResourcePolicy(sec, "secret", account, region, model.PolicyResource, text)
		}
	}

	// Lambda
	if fns, err := s.listFunctions(ctx, region); err != nil {
		b.listGap(account, "lambda ListFunctions in "+region, err, pfx("lambda"))
	} else {
		for _, f := range fns {
			text, err := s.functionPolicy(ctx, region, f.Name)
			if err != nil {
				b.resourceGap(f.ARN, "lambda GetPolicy", err)
			}
			b.addResourcePolicy(f.ARN, "function", account, region, model.PolicyResource, text)
		}
	}

	// ECR
	if repos, err := s.listRepositories(ctx, region); err != nil {
		b.listGap(account, "ecr DescribeRepositories in "+region, err, pfx("ecr"))
	} else {
		for _, r := range repos {
			text, err := s.repositoryPolicy(ctx, region, r.Name)
			if err != nil {
				b.resourceGap(r.ARN, "ecr GetRepositoryPolicy", err)
			}
			b.addResourcePolicy(r.ARN, "repository", account, region, model.PolicyResource, text)
		}
	}

	// VPC endpoints
	if eps, err := s.describeVPCEndpoints(ctx, region); err != nil {
		b.gap(account, errCode(err), "ec2 DescribeVpcEndpoints in "+region+": "+errDetail(err), Scope{Type: ScopeAccounts, Targets: []string{account}})
	} else {
		for _, e := range eps {
			arn := "arn:aws:ec2:" + region + ":" + firstNonEmpty(e.OwnerID, account) + ":vpc-endpoint/" + e.ID
			b.snap.Resources[arn] = &model.Resource{ARN: arn, Type: "vpce", AccountID: account, Region: region}
			if e.Policy == "" {
				continue
			}
			ref := b.parseDoc(model.PolicyVPCE, arn+"#policy", "", e.Policy, false, Scope{Type: ScopeAccounts, Targets: []string{account}})
			if ref.ok() {
				b.snap.VPCEPolicies[e.ID] = ref.id
			}
		}
	}
}

var errNoARN = &Error{Code: "NoQueueArn", Message: "the response has no QueueArn"}

// kmsGrant maps a ListGrants entry. A grantee that is a service principal
// ("lambda.amazonaws.com") is kept apart from an ARN grantee.
func kmsGrant(keyARN string, g kmsGrantRec) model.KMSGrant {
	out := model.KMSGrant{KeyARN: keyARN, GrantID: g.GrantID, RetiringPrincipal: g.RetiringPrincipal,
		ConstraintsECEquals: g.Constraints.Equals, ConstraintsECSubset: g.Constraints.Subset}
	if strings.HasSuffix(g.GranteePrincipal, ".amazonaws.com") && !strings.Contains(g.GranteePrincipal, ":") {
		out.GranteeServicePrincipal = g.GranteePrincipal
	} else {
		out.GranteePrincipal = g.GranteePrincipal
	}
	out.Operations = sortedStrings(g.Operations)
	if f, err := strconv.ParseFloat(g.CreationDate.String(), 64); err == nil && f > 0 {
		out.CreatedAt = time.Unix(int64(f), 0).UTC()
	}
	return out
}
