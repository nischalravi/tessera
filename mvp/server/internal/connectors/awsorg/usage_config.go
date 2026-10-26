package awsorg

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Usage ingest settings (issue #644, LP-1). They are optional: a connector with
// no "usage" in its config collects the estate only, as before.

// Limits on the usage settings and on what one run reads. They bound what a
// customer-supplied bucket can make the collector do.
const (
	DefaultBackfillDays     = 30
	MaxBackfillDays         = 90
	DefaultMaxObjectsPerRun = 2000
	MaxMaxObjectsPerRun     = 20000
	DefaultAdvisorPerRun    = 100
	MaxAdvisorPerRun        = 1000
)

var (
	// trailPrefixRE is the characters of a key prefix we accept. Keys become
	// request paths, so anything that would need escaping is refused.
	trailPrefixRE = regexp.MustCompile(`^[A-Za-z0-9_./-]{0,200}$`)
	orgIDRE       = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	trailARNRE    = regexp.MustCompile(`^arn:aws[a-z-]*:cloudtrail:([a-z]{2}(?:-[a-z]+)+-[0-9]):([0-9]{12}):trail/[A-Za-z0-9._-]{3,128}$`)
	kmsARNRE      = regexp.MustCompile(`^arn:aws[a-z-]*:kms:[a-z]{2}(?:-[a-z]+)+-[0-9]:[0-9]{12}:(key/[0-9a-fA-F-]{36}|alias/[A-Za-z0-9/_-]{1,256})$`)
)

// UsageConfig says which usage sources a connector ingests.
type UsageConfig struct {
	// CloudTrail reads the organization trail's log files from S3.
	CloudTrail *CloudTrailConfig `json:"cloudtrail,omitempty"`
	// AccessAdvisor reads IAM Access Advisor (last-accessed data) for each user
	// and role of the latest snapshot. It makes two IAM calls or more per
	// principal, so it is opt-in.
	AccessAdvisor bool `json:"access_advisor,omitempty"`
	// AdvisorPerRun bounds the principals read per run (default 100); the rest
	// are read by later runs, so a large estate is covered over several runs.
	AdvisorPerRun int `json:"advisor_per_run,omitempty"`
}

// CloudTrailConfig is the trail the customer gives us: where its logs are.
// The connector reads it with the reader role of AccountID, so the customer
// lets that role list and read the log prefix (TrailReaderPolicy) and, for a
// trail encrypted with a KMS key, lets it decrypt with the key policy (kms:Decrypt
// is not a read-only action, so it cannot be in ReaderPolicy).
type CloudTrailConfig struct {
	Bucket string `json:"bucket"`
	// Prefix is the trail's S3 key prefix, without slashes at the ends; empty
	// for a trail with none.
	Prefix string `json:"prefix,omitempty"`
	// Region is the bucket's region (default: the first of the connector's regions).
	Region string `json:"region,omitempty"`
	// AccountID owns the bucket (usually the log archive account); the reader
	// role is assumed there, and every request names it as the expected bucket
	// owner. Default: the management account.
	AccountID string `json:"account_id,omitempty"`
	// OrganizationID is the o-... id for an organization trail, which stores
	// its logs under AWSLogs/<org id>/<account>/. Empty for a plain trail.
	OrganizationID string `json:"organization_id,omitempty"`
	// TrailARN names the trail so its event selectors can be read, to tell
	// whether S3 data events are logged. Empty: data events are "unknown".
	TrailARN string `json:"trail_arn,omitempty"`
	// KMSKeyARN is the key the trail's logs are encrypted with, if any. It is
	// not used to call KMS: it makes an access error say what to grant.
	KMSKeyARN string `json:"kms_key_arn,omitempty"`
	// BackfillDays is how far back the first run reads (default 30, at most 90).
	BackfillDays int `json:"backfill_days,omitempty"`
	// MaxObjectsPerRun bounds the log files read per run (default 2000); the
	// cursor resumes where a run stopped.
	MaxObjectsPerRun int `json:"max_objects_per_run,omitempty"`
}

// validate normalizes c in the context of its connector's config.
func (u *UsageConfig) validate(cfg *Config) error {
	if u.AdvisorPerRun < 0 || u.AdvisorPerRun > MaxAdvisorPerRun {
		return fmt.Errorf("usage.advisor_per_run: between 0 and %d", MaxAdvisorPerRun)
	}
	if u.AdvisorPerRun == 0 {
		u.AdvisorPerRun = DefaultAdvisorPerRun
	}
	if u.CloudTrail != nil {
		return u.CloudTrail.validate(cfg)
	}
	return nil
}

func (c *CloudTrailConfig) validate(cfg *Config) error {
	if !bucketRE.MatchString(c.Bucket) {
		return errors.New("usage.cloudtrail.bucket is not an S3 bucket name")
	}
	c.Prefix = strings.Trim(c.Prefix, "/")
	if !trailPrefixRE.MatchString(c.Prefix) || strings.Contains(c.Prefix, "//") || strings.Contains(c.Prefix, "..") {
		return errors.New("usage.cloudtrail.prefix: letters, digits and _ . - / only, 200 characters at most")
	}
	if c.Region == "" && len(cfg.Regions) > 0 {
		c.Region = cfg.Regions[0]
	}
	if !regionRE.MatchString(c.Region) {
		return errors.New("usage.cloudtrail.region is not a region name")
	}
	if c.AccountID == "" {
		c.AccountID = cfg.ManagementAccountID
	}
	if !accountRE.MatchString(c.AccountID) {
		return errors.New("usage.cloudtrail.account_id: the 12-digit account that owns the bucket is required")
	}
	if c.OrganizationID != "" && !orgIDRE.MatchString(c.OrganizationID) {
		return errors.New("usage.cloudtrail.organization_id is not an organization id (o-...)")
	}
	if c.TrailARN != "" && !trailARNRE.MatchString(c.TrailARN) {
		return errors.New("usage.cloudtrail.trail_arn is not a CloudTrail trail ARN")
	}
	if c.KMSKeyARN != "" && !kmsARNRE.MatchString(c.KMSKeyARN) {
		return errors.New("usage.cloudtrail.kms_key_arn is not a KMS key or alias ARN")
	}
	if c.BackfillDays < 0 || c.BackfillDays > MaxBackfillDays {
		return fmt.Errorf("usage.cloudtrail.backfill_days: between 0 and %d", MaxBackfillDays)
	}
	if c.BackfillDays == 0 {
		c.BackfillDays = DefaultBackfillDays
	}
	if c.MaxObjectsPerRun < 0 || c.MaxObjectsPerRun > MaxMaxObjectsPerRun {
		return fmt.Errorf("usage.cloudtrail.max_objects_per_run: between 0 and %d", MaxMaxObjectsPerRun)
	}
	if c.MaxObjectsPerRun == 0 {
		c.MaxObjectsPerRun = DefaultMaxObjectsPerRun
	}
	return nil
}

// logRoot is the key prefix every log file of the trail lies under:
// "<prefix>/AWSLogs/[<org id>/]". It ends with a slash.
func (c *CloudTrailConfig) logRoot() string {
	root := "AWSLogs/"
	if c.Prefix != "" {
		root = c.Prefix + "/" + root
	}
	if c.OrganizationID != "" {
		root += c.OrganizationID + "/"
	}
	return root
}

// partition is the AWS partition of the trail (aws, aws-cn, aws-us-gov), read
// from TrailARN; "aws" when it is unset or names none that is known.
func (c *CloudTrailConfig) partition() string {
	if rest, ok := strings.CutPrefix(c.TrailARN, "arn:"); ok {
		p, _, _ := strings.Cut(rest, ":")
		switch p {
		case "aws-cn", "aws-us-gov":
			return p
		}
	}
	return "aws"
}

// TrailARNParts returns the region and account of TrailARN ("" when unset).
func (c *CloudTrailConfig) trailParts() (region, account string) {
	m := trailARNRE.FindStringSubmatch(c.TrailARN)
	if m == nil {
		return "", ""
	}
	return m[1], m[2]
}

// TrailReaderPolicy returns the policy to attach to the reader role of the
// bucket's account, next to ReaderPolicy: it lists the log prefix and reads the
// log files under it, and nothing else. Unlike ReaderPolicy it is scoped to the
// bucket: s3:GetObject on every object would be far more than the connector
// needs. CheckReadOnly accepts it.
func TrailReaderPolicy(c CloudTrailConfig) []byte {
	root := c.logRoot()
	part := c.partition()
	b, err := json.MarshalIndent(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{
				"Sid": "TesseraTrailList", "Effect": "Allow", "Action": []string{"s3:ListBucket"},
				"Resource":  "arn:" + part + ":s3:::" + c.Bucket,
				"Condition": map[string]any{"StringLike": map[string]any{"s3:prefix": []string{root + "*"}}},
			},
			map[string]any{
				"Sid": "TesseraTrailRead", "Effect": "Allow", "Action": []string{"s3:GetObject"},
				"Resource": "arn:" + part + ":s3:::" + c.Bucket + "/" + root + "*",
			},
		},
	}, "", "  ")
	if err != nil {
		panic(err) // static data
	}
	return b
}
