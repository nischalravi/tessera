package awsorg

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
)

// The remaining read-only APIs: KMS (ListKeys, DescribeKey, GetKeyPolicy,
// ListGrants), SQS (ListQueues, GetQueueAttributes), SNS (ListTopics,
// GetTopicAttributes), Secrets Manager (ListSecrets, GetResourcePolicy),
// Lambda (ListFunctions, GetPolicy), ECR (DescribeRepositories,
// GetRepositoryPolicy), EC2 (DescribeVpcEndpoints) and Identity Center
// (ListInstances, ListPermissionSets, DescribePermissionSet,
// ListAccountAssignments).

// ---------------------------------------------------------------- KMS

const kmsTarget = "TrentService."

type kmsKey struct{ ID, ARN string }

func (s session) listKeys(ctx context.Context, region string) ([]kmsKey, error) {
	var out []kmsKey
	err := paginate(ctx, func(marker string) (string, error) {
		in := map[string]any{"Limit": 1000}
		if marker != "" {
			in["Marker"] = marker
		}
		var r struct {
			Keys []struct {
				KeyID  string `json:"KeyId"`
				KeyARN string `json:"KeyArn"`
			} `json:"Keys"`
			NextMarker string `json:"NextMarker"`
			Truncated  bool   `json:"Truncated"`
		}
		if err := s.jsonCall(ctx, svcKMS, region, kmsTarget+"ListKeys", json11, in, &r); err != nil {
			return "", err
		}
		for _, k := range r.Keys {
			out = append(out, kmsKey{ID: k.KeyID, ARN: k.KeyARN})
		}
		if r.Truncated {
			return r.NextMarker, nil
		}
		return "", nil
	})
	return out, err
}

// describeKey returns the key's ARN as KMS reports it.
func (s session) describeKey(ctx context.Context, region, keyID string) (string, error) {
	var r struct {
		KeyMetadata struct {
			ARN string `json:"Arn"`
		} `json:"KeyMetadata"`
	}
	if err := s.jsonCall(ctx, svcKMS, region, kmsTarget+"DescribeKey", json11, map[string]any{"KeyId": keyID}, &r); err != nil {
		return "", err
	}
	return r.KeyMetadata.ARN, nil
}

func (s session) getKeyPolicy(ctx context.Context, region, keyID string) (string, error) {
	var r struct {
		Policy string `json:"Policy"`
	}
	err := s.jsonCall(ctx, svcKMS, region, kmsTarget+"GetKeyPolicy", json11, map[string]any{"KeyId": keyID, "PolicyName": "default"}, &r)
	return r.Policy, err
}

type kmsGrantRec struct {
	GrantID           string `json:"GrantId"`
	GranteePrincipal  string `json:"GranteePrincipal"`
	RetiringPrincipal string `json:"RetiringPrincipal"`
	Operations        []string
	Constraints       struct {
		Subset map[string]string `json:"EncryptionContextSubset"`
		Equals map[string]string `json:"EncryptionContextEquals"`
	} `json:"Constraints"`
	CreationDate json.Number `json:"CreationDate"` // epoch seconds, fractional
}

func (s session) listGrants(ctx context.Context, region, keyID string) ([]kmsGrantRec, error) {
	var out []kmsGrantRec
	err := paginate(ctx, func(marker string) (string, error) {
		in := map[string]any{"KeyId": keyID, "Limit": 100}
		if marker != "" {
			in["Marker"] = marker
		}
		var r struct {
			Grants     []kmsGrantRec `json:"Grants"`
			NextMarker string        `json:"NextMarker"`
			Truncated  bool          `json:"Truncated"`
		}
		if err := s.jsonCall(ctx, svcKMS, region, kmsTarget+"ListGrants", json11, in, &r); err != nil {
			return "", err
		}
		out = append(out, r.Grants...)
		if r.Truncated {
			return r.NextMarker, nil
		}
		return "", nil
	})
	return out, err
}

// ---------------------------------------------------------------- SQS

func (s session) listQueueURLs(ctx context.Context, region string) ([]string, error) {
	var out []string
	err := paginate(ctx, func(tok string) (string, error) {
		in := map[string]any{"MaxResults": 1000}
		if tok != "" {
			in["NextToken"] = tok
		}
		var r struct {
			QueueURLs []string `json:"QueueUrls"`
			NextToken string   `json:"NextToken"`
		}
		if err := s.jsonCall(ctx, svcSQS, region, "AmazonSQS.ListQueues", json10, in, &r); err != nil {
			return "", err
		}
		out = append(out, r.QueueURLs...)
		return r.NextToken, nil
	})
	return out, err
}

// queuePolicy returns the queue's ARN and policy text ("" when it has none).
func (s session) queuePolicy(ctx context.Context, region, queueURL string) (arn, policy string, err error) {
	var r struct {
		Attributes map[string]string `json:"Attributes"`
	}
	err = s.jsonCall(ctx, svcSQS, region, "AmazonSQS.GetQueueAttributes", json10,
		map[string]any{"QueueUrl": queueURL, "AttributeNames": []string{"Policy", "QueueArn"}}, &r)
	return r.Attributes["QueueArn"], r.Attributes["Policy"], err
}

// ---------------------------------------------------------------- SNS

func (s session) listTopics(ctx context.Context, region string) ([]string, error) {
	var out []string
	err := paginate(ctx, func(tok string) (string, error) {
		p := url.Values{}
		if tok != "" {
			p.Set("NextToken", tok)
		}
		var r struct {
			Result struct {
				Topics []string `xml:"Topics>member>TopicArn"`
				Next   string   `xml:"NextToken"`
			} `xml:"ListTopicsResult"`
		}
		if err := s.query(ctx, svcSNS, region, "2010-03-31", "ListTopics", p, &r); err != nil {
			return "", err
		}
		out = append(out, r.Result.Topics...)
		return r.Result.Next, nil
	})
	return out, err
}

func (s session) topicPolicy(ctx context.Context, region, topicARN string) (string, error) {
	var r struct {
		Result struct {
			Entries []struct {
				Key   string `xml:"key"`
				Value string `xml:"value"`
			} `xml:"Attributes>entry"`
		} `xml:"GetTopicAttributesResult"`
	}
	if err := s.query(ctx, svcSNS, region, "2010-03-31", "GetTopicAttributes", url.Values{"TopicArn": {topicARN}}, &r); err != nil {
		return "", err
	}
	for _, e := range r.Result.Entries {
		if e.Key == "Policy" {
			return e.Value, nil
		}
	}
	return "", nil
}

// ---------------------------------------------------------------- Secrets Manager

func (s session) listSecretARNs(ctx context.Context, region string) ([]string, error) {
	var out []string
	err := paginate(ctx, func(tok string) (string, error) {
		in := map[string]any{"MaxResults": 100}
		if tok != "" {
			in["NextToken"] = tok
		}
		var r struct {
			SecretList []struct {
				ARN string `json:"ARN"`
			} `json:"SecretList"`
			NextToken string `json:"NextToken"`
		}
		if err := s.jsonCall(ctx, svcSecrets, region, "secretsmanager.ListSecrets", json11, in, &r); err != nil {
			return "", err
		}
		for _, x := range r.SecretList {
			out = append(out, x.ARN)
		}
		return r.NextToken, nil
	})
	return out, err
}

// secretPolicy returns the secret's resource policy text ("" when it has none).
func (s session) secretPolicy(ctx context.Context, region, secretARN string) (string, error) {
	var r struct {
		ResourcePolicy string `json:"ResourcePolicy"`
	}
	err := s.jsonCall(ctx, svcSecrets, region, "secretsmanager.GetResourcePolicy", json11, map[string]any{"SecretId": secretARN}, &r)
	return r.ResourcePolicy, err
}

// ---------------------------------------------------------------- Lambda

type lambdaFunction struct{ Name, ARN string }

var lambdaNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (s session) listFunctions(ctx context.Context, region string) ([]lambdaFunction, error) {
	var out []lambdaFunction
	err := paginate(ctx, func(marker string) (string, error) {
		q := url.Values{"MaxItems": {"50"}}
		if marker != "" {
			q.Set("Marker", marker)
		}
		b, err := s.rest(ctx, svcLambda, region, "lambda."+region+".amazonaws.com", "ListFunctions", "/2015-03-31/functions", q, nil)
		if err != nil {
			return "", err
		}
		var r struct {
			Functions []struct {
				Name string `json:"FunctionName"`
				ARN  string `json:"FunctionArn"`
			} `json:"Functions"`
			NextMarker string `json:"NextMarker"`
		}
		if err := json.Unmarshal(b, &r); err != nil {
			return "", fmt.Errorf("aws: lambda ListFunctions: bad JSON response: %w", err)
		}
		for _, f := range r.Functions {
			out = append(out, lambdaFunction{Name: f.Name, ARN: f.ARN})
		}
		return r.NextMarker, nil
	})
	return out, err
}

// functionPolicy returns the function's resource policy text ("" when it has none).
func (s session) functionPolicy(ctx context.Context, region, name string) (string, error) {
	if !lambdaNameRE.MatchString(name) {
		return "", fmt.Errorf("aws: lambda: refusing function name %q", clip(name, 80))
	}
	b, err := s.rest(ctx, svcLambda, region, "lambda."+region+".amazonaws.com", "GetPolicy", "/2015-03-31/functions/"+name+"/policy", nil, nil)
	if IsCode(err, "ResourceNotFoundException") {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var r struct {
		Policy string `json:"Policy"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return "", fmt.Errorf("aws: lambda GetPolicy: bad JSON response: %w", err)
	}
	return r.Policy, nil
}

// ---------------------------------------------------------------- ECR

const ecrTarget = "AmazonEC2ContainerRegistry_V20150921."

type ecrRepo struct{ Name, ARN string }

func (s session) listRepositories(ctx context.Context, region string) ([]ecrRepo, error) {
	var out []ecrRepo
	err := paginate(ctx, func(tok string) (string, error) {
		in := map[string]any{"maxResults": 1000}
		if tok != "" {
			in["nextToken"] = tok
		}
		var r struct {
			Repositories []struct {
				ARN  string `json:"repositoryArn"`
				Name string `json:"repositoryName"`
			} `json:"repositories"`
			NextToken string `json:"nextToken"`
		}
		if err := s.jsonCall(ctx, svcECR, region, ecrTarget+"DescribeRepositories", json11, in, &r); err != nil {
			return "", err
		}
		for _, x := range r.Repositories {
			out = append(out, ecrRepo{Name: x.Name, ARN: x.ARN})
		}
		return r.NextToken, nil
	})
	return out, err
}

// repositoryPolicy returns the repository policy text ("" when it has none).
func (s session) repositoryPolicy(ctx context.Context, region, name string) (string, error) {
	var r struct {
		PolicyText string `json:"policyText"`
	}
	err := s.jsonCall(ctx, svcECR, region, ecrTarget+"GetRepositoryPolicy", json11, map[string]any{"repositoryName": name}, &r)
	if IsCode(err, "RepositoryPolicyNotFoundException") {
		return "", nil
	}
	return r.PolicyText, err
}

// ---------------------------------------------------------------- EC2 VPC endpoints

type vpcEndpoint struct{ ID, OwnerID, Policy string }

func (s session) describeVPCEndpoints(ctx context.Context, region string) ([]vpcEndpoint, error) {
	var out []vpcEndpoint
	err := paginate(ctx, func(tok string) (string, error) {
		p := url.Values{"MaxResults": {"1000"}}
		if tok != "" {
			p.Set("NextToken", tok)
		}
		var r struct {
			Endpoints []struct {
				ID     string `xml:"vpcEndpointId"`
				Owner  string `xml:"ownerId"`
				Policy string `xml:"policyDocument"`
			} `xml:"vpcEndpointSet>item"`
			Next string `xml:"nextToken"`
		}
		if err := s.query(ctx, svcEC2, region, "2016-11-15", "DescribeVpcEndpoints", p, &r); err != nil {
			return "", err
		}
		for _, e := range r.Endpoints {
			out = append(out, vpcEndpoint{ID: e.ID, OwnerID: e.Owner, Policy: e.Policy})
		}
		return r.Next, nil
	})
	return out, err
}

// ---------------------------------------------------------------- Identity Center (sso-admin)

const ssoTarget = "SWBExternalService."

type ssoInstance struct{ ARN, IdentityStoreID string }

func (s session) listSSOInstances(ctx context.Context, region string) ([]ssoInstance, error) {
	var out []ssoInstance
	err := paginate(ctx, func(tok string) (string, error) {
		in := map[string]any{"MaxResults": 100}
		if tok != "" {
			in["NextToken"] = tok
		}
		var r struct {
			Instances []struct {
				ARN     string `json:"InstanceArn"`
				StoreID string `json:"IdentityStoreId"`
			} `json:"Instances"`
			NextToken string `json:"NextToken"`
		}
		if err := s.jsonCall(ctx, svcSSO, region, ssoTarget+"ListInstances", json11, in, &r); err != nil {
			return "", err
		}
		for _, i := range r.Instances {
			out = append(out, ssoInstance{ARN: i.ARN, IdentityStoreID: i.StoreID})
		}
		return r.NextToken, nil
	})
	return out, err
}

func (s session) listPermissionSets(ctx context.Context, region, instanceARN string) ([]string, error) {
	var out []string
	err := paginate(ctx, func(tok string) (string, error) {
		in := map[string]any{"InstanceArn": instanceARN, "MaxResults": 100}
		if tok != "" {
			in["NextToken"] = tok
		}
		var r struct {
			PermissionSets []string `json:"PermissionSets"`
			NextToken      string   `json:"NextToken"`
		}
		if err := s.jsonCall(ctx, svcSSO, region, ssoTarget+"ListPermissionSets", json11, in, &r); err != nil {
			return "", err
		}
		out = append(out, r.PermissionSets...)
		return r.NextToken, nil
	})
	return out, err
}

func (s session) describePermissionSetName(ctx context.Context, region, instanceARN, setARN string) (string, error) {
	var r struct {
		PermissionSet struct {
			Name string `json:"Name"`
		} `json:"PermissionSet"`
	}
	err := s.jsonCall(ctx, svcSSO, region, ssoTarget+"DescribePermissionSet", json11,
		map[string]any{"InstanceArn": instanceARN, "PermissionSetArn": setARN}, &r)
	return r.PermissionSet.Name, err
}

// SSOAssignment is one Identity Center assignment of a permission set to a
// principal in an account. PrincipalID is the opaque Identity Store id: the
// connector does not read identitystore, so names are not resolved.
type SSOAssignment struct {
	AccountID         string `json:"account_id"`
	PermissionSetARN  string `json:"permission_set_arn"`
	PermissionSetName string `json:"permission_set_name"`
	PrincipalID       string `json:"principal_id"`
	PrincipalType     string `json:"principal_type"` // USER | GROUP
	RoleARN           string `json:"role_arn"`       // the AWSReservedSSO_ role in the account, "" if not found
}

func (s session) listAccountAssignments(ctx context.Context, region, instanceARN, setARN, account string) ([]SSOAssignment, error) {
	var out []SSOAssignment
	err := paginate(ctx, func(tok string) (string, error) {
		in := map[string]any{"InstanceArn": instanceARN, "PermissionSetArn": setARN, "AccountId": account, "MaxResults": 100}
		if tok != "" {
			in["NextToken"] = tok
		}
		var r struct {
			AccountAssignments []struct {
				AccountID     string `json:"AccountId"`
				SetARN        string `json:"PermissionSetArn"`
				PrincipalID   string `json:"PrincipalId"`
				PrincipalType string `json:"PrincipalType"`
			} `json:"AccountAssignments"`
			NextToken string `json:"NextToken"`
		}
		if err := s.jsonCall(ctx, svcSSO, region, ssoTarget+"ListAccountAssignments", json11, in, &r); err != nil {
			return "", err
		}
		for _, a := range r.AccountAssignments {
			out = append(out, SSOAssignment{AccountID: a.AccountID, PermissionSetARN: a.SetARN, PrincipalID: a.PrincipalID, PrincipalType: a.PrincipalType})
		}
		return r.NextToken, nil
	})
	return out, err
}
