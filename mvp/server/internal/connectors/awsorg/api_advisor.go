package awsorg

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// IAM Access Advisor (issue #644): iam:GenerateServiceLastAccessedDetails
// starts a report for one user or role, and iam:GetServiceLastAccessedDetails
// reads it. ACTION_LEVEL gives, for the services AWS tracks per action (S3, EC2,
// IAM, Lambda and a few more), the last time each action was used; for every
// other service the report is service-level, and the ingest records "<service>:*".
// Both are read actions: Generate only starts a report.

const (
	advisorPollEvery = 1 * time.Second
	advisorMaxPolls  = 60
	advisorMaxItems  = 1000
)

type advisorAction struct {
	Name         string `xml:"ActionName"`
	LastAccessed string `xml:"LastAccessedTime"`
}

type advisorService struct {
	Namespace         string          `xml:"ServiceNamespace"`
	LastAuthenticated string          `xml:"LastAuthenticated"`
	Actions           []advisorAction `xml:"TrackedActionsLastAccessed>member"`
}

type advisorReport struct {
	Services []advisorService
}

type generateLastAccessedResp struct {
	Result struct {
		JobID string `xml:"JobId"`
	} `xml:"GenerateServiceLastAccessedDetailsResult"`
}

type getLastAccessedResp struct {
	Result struct {
		Status    string           `xml:"JobStatus"`
		Truncated bool             `xml:"IsTruncated"`
		Marker    string           `xml:"Marker"`
		Services  []advisorService `xml:"ServicesLastAccessed>member"`
		ErrorCode string           `xml:"Error>Code"`
		ErrorMsg  string           `xml:"Error>Message"`
	} `xml:"GetServiceLastAccessedDetailsResult"`
}

// errAdvisorNotReady is returned when a report is still in progress after the
// polling budget: the run records a gap and the principal is read again later.
var errAdvisorNotReady = errors.New("aws: iam GetServiceLastAccessedDetails: the report is not ready")

// serviceLastAccessed runs one Access Advisor report for a user or role and
// returns every page of it. wait sleeps between polls (the client's, so a test
// does not really wait).
func (s session) serviceLastAccessed(ctx context.Context, arn string) (*advisorReport, error) {
	var g generateLastAccessedResp
	if err := s.query(ctx, svcIAM, "us-east-1", "2010-05-08", "GenerateServiceLastAccessedDetails",
		url.Values{"Arn": {arn}, "Granularity": {"ACTION_LEVEL"}}, &g); err != nil {
		return nil, err
	}
	job := g.Result.JobID
	if job == "" || len(job) > 256 {
		return nil, errors.New("aws: iam GenerateServiceLastAccessedDetails: no job id")
	}
	rep := &advisorReport{}
	marker := ""
	for polls := 0; ; {
		p := url.Values{"JobId": {job}, "MaxItems": {fmt.Sprint(advisorMaxItems)}}
		if marker != "" {
			p.Set("Marker", marker)
		}
		var r getLastAccessedResp
		if err := s.query(ctx, svcIAM, "us-east-1", "2010-05-08", "GetServiceLastAccessedDetails", p, &r); err != nil {
			return nil, err
		}
		switch r.Result.Status {
		case "COMPLETED":
		case "FAILED":
			return nil, &Error{Service: svcIAM, Op: "GetServiceLastAccessedDetails", Status: 200,
				Code: firstNonEmpty(r.Result.ErrorCode, "JobFailed"), Message: clip(r.Result.ErrorMsg, 300)}
		default: // IN_PROGRESS
			if polls++; polls > advisorMaxPolls {
				return nil, errAdvisorNotReady
			}
			if err := s.cl.sleep(ctx, advisorPollEvery); err != nil {
				return nil, err
			}
			continue
		}
		rep.Services = append(rep.Services, r.Result.Services...)
		if !r.Result.Truncated {
			return rep, nil
		}
		if r.Result.Marker == "" || r.Result.Marker == marker {
			return nil, errors.New("aws: iam GetServiceLastAccessedDetails: truncated page with no new marker")
		}
		marker = r.Result.Marker
		if len(rep.Services) > 5000 {
			return nil, errors.New("aws: iam GetServiceLastAccessedDetails: more than 5000 services")
		}
	}
}
