package awsorg

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// S3 and S3 Control (REST/XML). Read actions only: ListAllMyBuckets,
// GetBucketPolicy, GetBucketAcl, GetBucketOwnershipControls,
// GetBucketPublicAccessBlock; s3control GetPublicAccessBlock (the account
// level), ListAccessPoints, GetAccessPointPolicy.

type s3Bucket struct {
	Name, Region string
}

type s3ListResp struct {
	Owner struct {
		ID string `xml:"ID"`
	} `xml:"Owner"`
	Buckets []struct {
		Name   string `xml:"Name"`
		Region string `xml:"BucketRegion"`
	} `xml:"Buckets>Bucket"`
	Token string `xml:"ContinuationToken"`
}

// listBuckets returns every bucket of the account and its canonical owner id.
func (s session) listBuckets(ctx context.Context, region string) (buckets []s3Bucket, ownerID string, err error) {
	err = paginate(ctx, func(tok string) (string, error) {
		q := url.Values{"max-buckets": {"1000"}}
		if tok != "" {
			q.Set("continuation-token", tok)
		}
		body, err := s.rest(ctx, svcS3, region, "s3."+region+".amazonaws.com", "ListAllMyBuckets", "/", q, nil)
		if err != nil {
			return "", err
		}
		var r s3ListResp
		if err := decodeXML(body, &r, svcS3, "ListAllMyBuckets"); err != nil {
			return "", err
		}
		ownerID = r.Owner.ID
		for _, b := range r.Buckets {
			buckets = append(buckets, s3Bucket{Name: b.Name, Region: b.Region})
		}
		return r.Token, nil
	})
	return buckets, ownerID, err
}

// bucketRequest is the host and path of a bucket-level request: virtual-hosted
// style, or path style for names with dots (a dot breaks the wildcard
// certificate of the virtual-hosted host).
func bucketRequest(bucket, region string) (host, path string, err error) {
	if !bucketRE.MatchString(bucket) {
		return "", "", fmt.Errorf("aws: s3: refusing bucket name %q", clip(bucket, 80))
	}
	if strings.Contains(bucket, ".") {
		return "s3." + region + ".amazonaws.com", "/" + bucket, nil
	}
	return bucket + ".s3." + region + ".amazonaws.com", "/", nil
}

func (s session) bucketGet(ctx context.Context, bucket, region, op, sub string) ([]byte, error) {
	host, path, err := bucketRequest(bucket, region)
	if err != nil {
		return nil, err
	}
	return s.rest(ctx, svcS3, region, host, op, path, url.Values{sub: {""}}, nil)
}

// getBucketPolicy returns the policy text, or "" when the bucket has none.
func (s session) getBucketPolicy(ctx context.Context, bucket, region string) (string, error) {
	b, err := s.bucketGet(ctx, bucket, region, "GetBucketPolicy", "policy")
	if IsCode(err, "NoSuchBucketPolicy") {
		return "", nil
	}
	return string(b), err
}

type s3ACL struct {
	Grants []struct {
		Grantee struct {
			Type  string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
			ID    string `xml:"ID"`
			URI   string `xml:"URI"`
			Email string `xml:"EmailAddress"`
		} `xml:"Grantee"`
		Permission string `xml:"Permission"`
	} `xml:"AccessControlList>Grant"`
}

func (s session) getBucketACL(ctx context.Context, bucket, region string) (*s3ACL, error) {
	b, err := s.bucketGet(ctx, bucket, region, "GetBucketAcl", "acl")
	if err != nil {
		return nil, err
	}
	var a s3ACL
	return &a, decodeXML(b, &a, svcS3, "GetBucketAcl")
}

// getOwnershipControls returns the bucket's object ownership setting. A bucket
// with no ownership controls (created before April 2023, never configured)
// behaves as ObjectWriter.
func (s session) getOwnershipControls(ctx context.Context, bucket, region string) (string, error) {
	b, err := s.bucketGet(ctx, bucket, region, "GetBucketOwnershipControls", "ownershipControls")
	if IsCode(err, "OwnershipControlsNotFoundError") {
		return "ObjectWriter", nil
	}
	if err != nil {
		return "", err
	}
	var r struct {
		Ownership string `xml:"Rule>ObjectOwnership"`
	}
	if err := decodeXML(b, &r, svcS3, "GetBucketOwnershipControls"); err != nil {
		return "", err
	}
	if r.Ownership == "" {
		return "", fmt.Errorf("aws: s3 GetBucketOwnershipControls: no ObjectOwnership")
	}
	return r.Ownership, nil
}

type s3BPA struct {
	BlockPublicAcls       bool `xml:"BlockPublicAcls"`
	IgnorePublicAcls      bool `xml:"IgnorePublicAcls"`
	BlockPublicPolicy     bool `xml:"BlockPublicPolicy"`
	RestrictPublicBuckets bool `xml:"RestrictPublicBuckets"`
}

// getBucketPublicAccessBlock returns the bucket's settings; all false when none are set.
func (s session) getBucketPublicAccessBlock(ctx context.Context, bucket, region string) (s3BPA, error) {
	b, err := s.bucketGet(ctx, bucket, region, "GetBucketPublicAccessBlock", "publicAccessBlock")
	if IsCode(err, "NoSuchPublicAccessBlockConfiguration") {
		return s3BPA{}, nil
	}
	if err != nil {
		return s3BPA{}, err
	}
	var r s3BPA
	return r, decodeXML(b, &r, svcS3, "GetBucketPublicAccessBlock")
}

func controlHost(account, region string) (string, error) {
	if !accountRE.MatchString(account) {
		return "", fmt.Errorf("aws: invalid account id %q", account)
	}
	return account + ".s3-control." + region + ".amazonaws.com", nil
}

func controlHeader(account string) http.Header { return http.Header{"X-Amz-Account-Id": {account}} }

// getAccountPublicAccessBlock is s3control GetPublicAccessBlock.
func (s session) getAccountPublicAccessBlock(ctx context.Context, account, region string) (s3BPA, error) {
	host, err := controlHost(account, region)
	if err != nil {
		return s3BPA{}, err
	}
	b, err := s.rest(ctx, svcS3, region, host, "GetPublicAccessBlock", "/v20180820/configuration/publicAccessBlock", nil, controlHeader(account))
	if IsCode(err, "NoSuchPublicAccessBlockConfiguration") {
		return s3BPA{}, nil
	}
	if err != nil {
		return s3BPA{}, err
	}
	var r s3BPA
	return r, decodeXML(b, &r, svcS3, "GetPublicAccessBlock")
}

type s3AccessPoint struct {
	Name, ARN, Bucket string
}

func (s session) listAccessPoints(ctx context.Context, account, region string) ([]s3AccessPoint, error) {
	host, err := controlHost(account, region)
	if err != nil {
		return nil, err
	}
	var out []s3AccessPoint
	err = paginate(ctx, func(tok string) (string, error) {
		q := url.Values{"maxResults": {"1000"}}
		if tok != "" {
			q.Set("nextToken", tok)
		}
		b, err := s.rest(ctx, svcS3, region, host, "ListAccessPoints", "/v20180820/accesspoint", q, controlHeader(account))
		if err != nil {
			return "", err
		}
		var r struct {
			AccessPoints []struct {
				Name   string `xml:"Name"`
				ARN    string `xml:"AccessPointArn"`
				Bucket string `xml:"Bucket"`
			} `xml:"AccessPointList>AccessPoint"`
			Next string `xml:"NextToken"`
		}
		if err := decodeXML(b, &r, svcS3, "ListAccessPoints"); err != nil {
			return "", err
		}
		for _, a := range r.AccessPoints {
			out = append(out, s3AccessPoint{Name: a.Name, ARN: a.ARN, Bucket: a.Bucket})
		}
		return r.Next, nil
	})
	return out, err
}

// validAccessPointName is the access point name grammar: a name from a list
// response becomes part of a request path, so anything else is refused.
func validAccessPointName(n string) bool {
	if len(n) < 3 || len(n) > 50 {
		return false
	}
	for _, c := range []byte(n) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// getAccessPointPolicy returns the access point's policy text, or "".
func (s session) getAccessPointPolicy(ctx context.Context, account, region, name string) (string, error) {
	host, err := controlHost(account, region)
	if err != nil {
		return "", err
	}
	if !validAccessPointName(name) {
		return "", fmt.Errorf("aws: s3control: refusing access point name %q", clip(name, 80))
	}
	b, err := s.rest(ctx, svcS3, region, host, "GetAccessPointPolicy", "/v20180820/accesspoint/"+name+"/policy", nil, controlHeader(account))
	if IsCode(err, "NoSuchAccessPointPolicy") {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var r struct {
		Policy string `xml:"Policy"`
	}
	if err := xml.Unmarshal(b, &r); err != nil {
		return "", fmt.Errorf("aws: s3control GetAccessPointPolicy: bad XML response: %w", err)
	}
	return r.Policy, nil
}
