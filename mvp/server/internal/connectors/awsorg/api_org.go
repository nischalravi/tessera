package awsorg

import (
	"context"
)

// AWS Organizations (JSON 1.1, target prefix AWSOrganizationsV20161128).
// Read actions only: DescribeOrganization, ListRoots,
// ListOrganizationalUnitsForParent, ListAccountsForParent, ListPolicies,
// DescribePolicy, ListTargetsForPolicy.

const (
	orgTarget  = "AWSOrganizationsV20161128."
	json11     = "application/x-amz-json-1.1"
	json10     = "application/x-amz-json-1.0"
	orgPageMax = 20 // the maximum MaxResults of the Organizations list calls
)

// Organizations policy types the evaluator uses.
const (
	policyTypeSCP = "SERVICE_CONTROL_POLICY"
	policyTypeRCP = "RESOURCE_CONTROL_POLICY"
)

type orgInfo struct {
	ID                string
	ManagementAccount string
	SCPEnabled        bool
	RCPEnabled        bool
}

type orgDescribeResp struct {
	Organization struct {
		ID                   string `json:"Id"`
		MasterAccountID      string `json:"MasterAccountId"`
		ManagementAccountID  string `json:"ManagementAccountId"`
		AvailablePolicyTypes []struct {
			Type   string `json:"Type"`
			Status string `json:"Status"`
		} `json:"AvailablePolicyTypes"`
	} `json:"Organization"`
}

func (s session) describeOrganization(ctx context.Context) (*orgInfo, error) {
	var r orgDescribeResp
	if err := s.jsonCall(ctx, svcOrganizations, "us-east-1", orgTarget+"DescribeOrganization", json11, struct{}{}, &r); err != nil {
		return nil, err
	}
	o := &orgInfo{ID: r.Organization.ID, ManagementAccount: firstNonEmpty(r.Organization.ManagementAccountID, r.Organization.MasterAccountID)}
	for _, t := range r.Organization.AvailablePolicyTypes {
		if t.Status != "ENABLED" {
			continue
		}
		switch t.Type {
		case policyTypeSCP:
			o.SCPEnabled = true
		case policyTypeRCP:
			o.RCPEnabled = true
		}
	}
	return o, nil
}

type orgNodeRef struct {
	ID, Name, Status string
}

func (s session) listRoots(ctx context.Context) ([]orgNodeRef, error) {
	var out []orgNodeRef
	err := paginate(ctx, func(tok string) (string, error) {
		var r struct {
			Roots []struct {
				ID   string `json:"Id"`
				Name string `json:"Name"`
			} `json:"Roots"`
			NextToken string `json:"NextToken"`
		}
		if err := s.jsonCall(ctx, svcOrganizations, "us-east-1", orgTarget+"ListRoots", json11, pageReq(tok, nil), &r); err != nil {
			return "", err
		}
		for _, x := range r.Roots {
			out = append(out, orgNodeRef{ID: x.ID, Name: x.Name})
		}
		return r.NextToken, nil
	})
	return out, err
}

func (s session) listOUs(ctx context.Context, parent string) ([]orgNodeRef, error) {
	var out []orgNodeRef
	err := paginate(ctx, func(tok string) (string, error) {
		var r struct {
			OrganizationalUnits []struct {
				ID   string `json:"Id"`
				Name string `json:"Name"`
			} `json:"OrganizationalUnits"`
			NextToken string `json:"NextToken"`
		}
		if err := s.jsonCall(ctx, svcOrganizations, "us-east-1", orgTarget+"ListOrganizationalUnitsForParent", json11,
			pageReq(tok, map[string]any{"ParentId": parent}), &r); err != nil {
			return "", err
		}
		for _, x := range r.OrganizationalUnits {
			out = append(out, orgNodeRef{ID: x.ID, Name: x.Name})
		}
		return r.NextToken, nil
	})
	return out, err
}

func (s session) listAccounts(ctx context.Context, parent string) ([]orgNodeRef, error) {
	var out []orgNodeRef
	err := paginate(ctx, func(tok string) (string, error) {
		var r struct {
			Accounts []struct {
				ID     string `json:"Id"`
				Name   string `json:"Name"`
				Status string `json:"Status"`
			} `json:"Accounts"`
			NextToken string `json:"NextToken"`
		}
		if err := s.jsonCall(ctx, svcOrganizations, "us-east-1", orgTarget+"ListAccountsForParent", json11,
			pageReq(tok, map[string]any{"ParentId": parent}), &r); err != nil {
			return "", err
		}
		for _, x := range r.Accounts {
			out = append(out, orgNodeRef{ID: x.ID, Name: x.Name, Status: x.Status})
		}
		return r.NextToken, nil
	})
	return out, err
}

type orgPolicySummary struct {
	ID, ARN, Name string
	AWSManaged    bool
}

func (s session) listPolicies(ctx context.Context, filter string) ([]orgPolicySummary, error) {
	var out []orgPolicySummary
	err := paginate(ctx, func(tok string) (string, error) {
		var r struct {
			Policies []struct {
				ID         string `json:"Id"`
				ARN        string `json:"Arn"`
				Name       string `json:"Name"`
				AWSManaged bool   `json:"AwsManaged"`
			} `json:"Policies"`
			NextToken string `json:"NextToken"`
		}
		if err := s.jsonCall(ctx, svcOrganizations, "us-east-1", orgTarget+"ListPolicies", json11,
			pageReq(tok, map[string]any{"Filter": filter}), &r); err != nil {
			return "", err
		}
		for _, x := range r.Policies {
			out = append(out, orgPolicySummary{ID: x.ID, ARN: x.ARN, Name: x.Name, AWSManaged: x.AWSManaged})
		}
		return r.NextToken, nil
	})
	return out, err
}

// describePolicy returns the policy document text.
func (s session) describePolicy(ctx context.Context, id string) (string, error) {
	var r struct {
		Policy struct {
			Content string `json:"Content"`
		} `json:"Policy"`
	}
	if err := s.jsonCall(ctx, svcOrganizations, "us-east-1", orgTarget+"DescribePolicy", json11,
		map[string]any{"PolicyId": id}, &r); err != nil {
		return "", err
	}
	return r.Policy.Content, nil
}

// listTargetsForPolicy returns the ids of the roots, OUs and accounts a policy
// is attached to.
func (s session) listTargetsForPolicy(ctx context.Context, id string) ([]string, error) {
	var out []string
	err := paginate(ctx, func(tok string) (string, error) {
		var r struct {
			Targets []struct {
				TargetID string `json:"TargetId"`
			} `json:"Targets"`
			NextToken string `json:"NextToken"`
		}
		if err := s.jsonCall(ctx, svcOrganizations, "us-east-1", orgTarget+"ListTargetsForPolicy", json11,
			pageReq(tok, map[string]any{"PolicyId": id}), &r); err != nil {
			return "", err
		}
		for _, x := range r.Targets {
			out = append(out, x.TargetID)
		}
		return r.NextToken, nil
	})
	return out, err
}

// pageReq builds a request body with MaxResults and the page token.
func pageReq(token string, extra map[string]any) map[string]any {
	m := map[string]any{"MaxResults": orgPageMax}
	for k, v := range extra {
		m[k] = v
	}
	if token != "" {
		m["NextToken"] = token
	}
	return m
}
