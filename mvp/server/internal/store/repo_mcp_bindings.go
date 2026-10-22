package store

import (
	"database/sql"
	"time"
)

// MCP resource bindings (schema/0700_mcp_resource_bindings.sql, issue #479):
// the authorization server issuer and the audience a registered MCP resource
// expects its tokens to carry. internal/mcpauth decides what a binding means;
// the store holds it.

// MCPResourceBinding binds a resource to its expected issuer and audience.
type MCPResourceBinding struct {
	ResourceID string
	Issuer     string
	Audience   string
	UpdatedBy  string
	UpdatedAt  time.Time
}

var (
	mcpBindingsPut = tq("mcp_resource_bindings.put", `
		INSERT INTO mcp_resource_bindings (tenant_id, resource_id, issuer, audience, updated_by, updated_at)
		VALUES (@tenant, @resource_id, @issuer, @audience, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, resource_id) DO UPDATE SET issuer = excluded.issuer, audience = excluded.audience,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
	mcpBindingsGet = tq("mcp_resource_bindings.get", `
		SELECT b.resource_id, b.issuer, b.audience, b.updated_by, b.updated_at FROM mcp_resource_bindings b
		WHERE b.tenant_id = @tenant AND b.resource_id = @resource_id`)
	mcpBindingsList = tq("mcp_resource_bindings.list", `
		SELECT b.resource_id, b.issuer, b.audience, b.updated_by, b.updated_at FROM mcp_resource_bindings b
		WHERE b.tenant_id = @tenant ORDER BY b.resource_id`)
)

func scanMCPBinding(s scanner) (*MCPResourceBinding, error) {
	var b MCPResourceBinding
	var at string
	if err := s.Scan(&b.ResourceID, &b.Issuer, &b.Audience, &b.UpdatedBy, &at); err != nil {
		return nil, err
	}
	var err error
	b.UpdatedAt, err = ParseRT(at)
	return &b, err
}

// PutMCPResourceBinding sets the binding of a resource (an update replaces it).
// The audience is unique per tenant: another resource bound to it is a
// constraint error.
func (tx *TenantTx) PutMCPResourceBinding(b *MCPResourceBinding) error {
	_, err := tx.exec(mcpBindingsPut, sql.Named("resource_id", b.ResourceID), sql.Named("issuer", b.Issuer),
		sql.Named("audience", b.Audience), sql.Named("updated_by", b.UpdatedBy), sql.Named("updated_at", RT(b.UpdatedAt)))
	return err
}

// MCPResourceBinding returns the explicit binding of a resource, or ErrNotFound
// (the resource is bound to the defaults).
func (tx *TenantTx) MCPResourceBinding(resourceID string) (*MCPResourceBinding, error) {
	return one(tx, scanMCPBinding, mcpBindingsGet, sql.Named("resource_id", resourceID))
}

// MCPResourceBindings lists the explicit bindings of the tenant.
func (tx *TenantTx) MCPResourceBindings() ([]*MCPResourceBinding, error) {
	return collect(tx, scanMCPBinding, mcpBindingsList)
}
