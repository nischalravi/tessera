package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Agent resource of draft-wzdk-scim-agent-resource. Discovery only records
// whether a service advertises it; Tessera does not provision /Agents yet.
const (
	AgentResourceType = "Agent"
	AgentSchema       = "urn:ietf:params:scim:schemas:core:2.0:Agent"
)

// Discovery is what a SCIM service says about itself (RFC 7643 section 6,
// RFC 7644 section 4): read-only, never used to gate Users/Groups provisioning.
type Discovery struct {
	// ServiceProviderConfig is true when /ServiceProviderConfig answered with a JSON object.
	ServiceProviderConfig bool `json:"service_provider_config"`
	// ResourceTypes lists the resource type names advertised.
	ResourceTypes []string `json:"resource_types"`
	// AgentAdvertised: resource type "Agent" or schema AgentSchema is listed.
	AgentAdvertised bool `json:"agent_advertised"`
}

type resourceType struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Schema string `json:"schema"`
}

// get reads one discovery document. A non-200 is an error here: the caller
// records it and carries on.
func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	status, body, err := c.do(ctx, http.MethodGet, "discover", path, nil, "", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d", path, status)
	}
	return body, nil
}

// Discover reads /ServiceProviderConfig and /ResourceTypes. Requests go through
// the client's safehttp transport, bodies are capped at maxBody, and unknown
// JSON fields are ignored (services add their own). A partial result is
// returned with the error when one document fails.
func (c *Client) Discover(ctx context.Context) (Discovery, error) {
	d := Discovery{ResourceTypes: []string{}}
	var errs []string
	if b, err := c.get(ctx, "/ServiceProviderConfig"); err != nil {
		errs = append(errs, err.Error())
	} else {
		var spc map[string]json.RawMessage
		if err := json.Unmarshal(b, &spc); err != nil || spc == nil {
			errs = append(errs, "/ServiceProviderConfig is not a JSON object")
		} else {
			d.ServiceProviderConfig = true
		}
	}
	if b, err := c.get(ctx, "/ResourceTypes"); err != nil {
		errs = append(errs, err.Error())
	} else if types, err := parseResourceTypes(b); err != nil {
		errs = append(errs, "/ResourceTypes: "+err.Error())
	} else {
		for _, t := range types {
			name := t.Name
			if name == "" {
				name = t.ID
			}
			if name != "" && len(d.ResourceTypes) < 100 {
				d.ResourceTypes = append(d.ResourceTypes, name)
			}
			if strings.EqualFold(t.Name, AgentResourceType) || strings.EqualFold(t.ID, AgentResourceType) || t.Schema == AgentSchema {
				d.AgentAdvertised = true
			}
		}
	}
	if len(errs) > 0 {
		return d, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return d, nil
}

// parseResourceTypes accepts a ListResponse or, as some services send, a bare array.
func parseResourceTypes(b []byte) ([]resourceType, error) {
	var list struct {
		Resources []resourceType `json:"Resources"`
	}
	if err := json.Unmarshal(b, &list); err == nil {
		return list.Resources, nil
	}
	var arr []resourceType
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil, fmt.Errorf("not a SCIM list")
	}
	return arr, nil
}
