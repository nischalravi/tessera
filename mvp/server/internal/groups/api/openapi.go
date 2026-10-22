package api

import (
	"encoding/json"
	"sort"
	"strings"
)

// OpenAPI document of the groups routes (design §10.11: "the OpenAPI document is
// generated from the route table"). OpenAPI takes the registered routes (the
// server's route table: method, pattern, permission, step-up) and describes the
// ones it covers with the summaries, parameters and bodies below. A route that
// is registered but has no entry here is an error of the test, so the document
// cannot silently miss one; the document is built, not embedded.

// RouteInfo is one registered route.
type RouteInfo struct {
	Method, Pattern, Perm string
	StepUp                bool
}

// Covers reports whether the groups document describes a route. GET /api/groups
// is not one: it lists the connected-system groups, not the native ones.
func Covers(method, pattern string) bool {
	if method == "GET" && pattern == "/api/groups" {
		return false
	}
	// the provisioning routes (GR-11) are not part of this document
	if strings.HasPrefix(pattern, "/api/groups/provisioners") {
		return false
	}
	return pattern == "/api/groups" || strings.HasPrefix(pattern, "/api/groups/") || strings.HasPrefix(pattern, "/api/groups:") ||
		strings.HasPrefix(pattern, "/scim/v2/") || (strings.HasPrefix(pattern, "/api/identities/") && strings.HasSuffix(pattern, "/groups"))
}

// opDoc describes one operation. Query and Header are "name:description" pairs;
// Body and Result name schemas of components; Created marks a 201 answer,
// Accepted a possible 202.
type opDoc struct {
	Key      string // "METHOD pattern"
	Summary  string
	Tag      string
	Query    []string
	Header   []string
	Body     string
	Result   string
	Created  bool
	Accepted bool
	// Approval marks a possible 202 that says a second admin must approve the
	// change (a SQL loader's configuration).
	Approval bool
}

const (
	qPage   = "limit:1 to 500, default 100|offset:rows to skip"
	qScimPg = "startIndex:1-based index of the first resource, default 1|count:resources per page, 0 to 200, default 100"
	qScim   = "filter:SCIM filter (eq ne co sw ew gt ge lt le pr, and or not, parentheses)|" + qScimPg +
		"|excludedAttributes:attributes to leave out|attributes:attributes to return"
	idemHdr = "Idempotency-Key:1 to 255 characters; a retry with the same key and request replays the first answer for 24 hours"
	asOfQ   = "as_of:RFC 3339 instant, not in the future"
	idQ     = "identity:identity id (default: the caller; another needs admin)"
)

var docList = []opDoc{
	{Key: "GET /api/groups/folders", Summary: "List folders the caller may view", Tag: "folders", Query: pairs("parent:folder id|scope:one or sub|q:name search|" + qPage)},
	{Key: "POST /api/groups/folders", Summary: "Create a folder", Tag: "folders", Created: true},
	{Key: "GET /api/groups/folders/{id}", Summary: "Get a folder", Tag: "folders"},
	{Key: "PATCH /api/groups/folders/{id}", Summary: "Edit or rename a folder", Tag: "folders"},
	{Key: "DELETE /api/groups/folders/{id}", Summary: "Delete an empty folder; with recursive=true, the folder and everything in it (step-up; a second admin approves a large or populated tree: 202)", Tag: "folders",
		Accepted: true, Query: pairs("recursive:true to delete the whole tree")},
	{Key: "GET /api/groups/folders/{id}/delete-plan", Summary: "What deleting the folder and everything in it would remove, and what blocks it", Tag: "folders"},
	{Key: "POST /api/groups/folders/{id}/move", Summary: "Move a folder", Tag: "folders"},
	{Key: "POST /api/groups/folders/{id}/copy", Summary: "Copy a folder", Tag: "folders", Created: true},
	{Key: "GET /api/groups/native", Summary: "List native groups the caller may view", Tag: "groups",
		Query: pairs("folder:folder id|scope:one or sub|q:name search|type:group or role|deleted:true to include deleted|" + qPage)},
	{Key: "POST /api/groups", Summary: "Create a group", Tag: "groups", Created: true},
	{Key: "GET /api/groups/{id}", Summary: "Get a group", Tag: "groups"},
	{Key: "PATCH /api/groups/{id}", Summary: "Edit or rename a group", Tag: "groups"},
	{Key: "DELETE /api/groups/{id}", Summary: "Delete a group (soft)", Tag: "groups"},
	{Key: "POST /api/groups/{id}/move", Summary: "Move a group", Tag: "groups"},
	{Key: "POST /api/groups/{id}/copy", Summary: "Copy a group", Tag: "groups", Created: true},
	{Key: "POST /api/groups/{id}/restore", Summary: "Restore a deleted group", Tag: "groups"},
	{Key: "POST /api/groups/{id}/purge", Summary: "Permanently delete a group that is already deleted (409 group_in_use while another group uses it)", Tag: "groups"},
	{Key: "POST /api/groups/{id}/convert-to-composite", Summary: "Turn a basic group into a composite", Tag: "groups", Accepted: true},
	{Key: "PUT /api/groups/{id}/composite", Summary: "Redefine a composite group", Tag: "groups", Accepted: true},
	{Key: "GET /api/groups/{id}/members", Summary: "List members: direct, indirect, effective or composite, now or as of a time", Tag: "members",
		Result: "MemberPage", Query: pairs("filter:direct (default), indirect, effective or composite|list:members (the built-in list)|" +
			"enabled:true or false (direct rows that count now or not)|q:member name or email|sort:name, -name, since or -since|" +
			"page:1-based page (instead of offset)|" + asOfQ + "|between:two RFC 3339 instants, comma separated, at most 366 days|" + qPage)},
	{Key: "POST /api/groups/{id}/members", Summary: "Add a member or update its dates", Tag: "members", Created: true, Accepted: true, Header: pairs(idemHdr)},
	{Key: "GET /api/groups/{id}/members/{member}", Summary: "Is the identity a member? With trace=true, every path that makes it one", Tag: "members",
		Result: "MemberTrace", Query: pairs("trace:true to list the paths")},
	{Key: "DELETE /api/groups/{id}/members/{member}", Summary: "Remove a direct member (an identity id or a group id)", Tag: "members", Accepted: true, Header: pairs(idemHdr)},
	{Key: "POST /api/groups/{id}/members:batch", Summary: "Add and remove members in one atomic (default) or independent batch of up to 1000 operations",
		Tag: "members", Body: "BatchRequest", Result: "BatchResponse", Accepted: true, Header: pairs(idemHdr)},
	{Key: "POST /api/groups:simulate", Summary: "Simulate changes: the membership and downstream diff, with nothing written", Tag: "simulation",
		Body: "SimulateRequest", Result: "SimulateResponse"},
	{Key: "GET /api/identities/{identity_id}/groups", Summary: "The groups an identity belongs to, now or as of a time", Tag: "members",
		Result: "GroupPage", Query: pairs("filter:effective (default), direct or indirect|list:members|" + asOfQ + "|" + qPage)},
	{Key: "GET /api/groups/{id}/privileges", Summary: "List the privileges granted on a group", Tag: "privileges"},
	{Key: "POST /api/groups/{id}/privileges", Summary: "Grant a privilege on a group", Tag: "privileges", Body: "PrivilegeGrant", Created: true},
	{Key: "GET /api/groups/{id}/privileges/effective", Summary: "Explain the privileges an identity holds on a group", Tag: "privileges", Query: pairs(idQ)},
	{Key: "DELETE /api/groups/{id}/privileges/{privilege_id}", Summary: "Revoke one privilege row", Tag: "privileges"},
	{Key: "GET /api/groups/folders/{id}/privileges", Summary: "List the privileges granted on a folder", Tag: "privileges"},
	{Key: "POST /api/groups/folders/{id}/privileges", Summary: "Grant a privilege on a folder", Tag: "privileges", Body: "PrivilegeGrant", Created: true},
	{Key: "GET /api/groups/folders/{id}/privileges/effective", Summary: "Explain the privileges an identity holds on a folder", Tag: "privileges", Query: pairs(idQ)},
	{Key: "DELETE /api/groups/folders/{id}/privileges/{privilege_id}", Summary: "Revoke one privilege row on a folder", Tag: "privileges"},
	{Key: "GET /api/groups/privileges/settings", Summary: "Read the tenant's privilege settings", Tag: "privileges"},
	{Key: "PUT /api/groups/privileges/settings", Summary: "Save the tenant's privilege settings", Tag: "privileges"},
	{Key: "PUT /api/groups/users/{id}/identity", Summary: "Link, relink or unlink a platform user's identity (two admins: the first answers 202 pending_second_admin)", Tag: "privileges"},
	{Key: "GET /api/groups/users/identity-requests", Summary: "Identity link changes waiting for a second admin", Tag: "privileges"},
	{Key: "GET /api/groups/pit/digests", Summary: "Daily Merkle digests of the change events", Tag: "history", Query: pairs("limit:digests to return")},
	{Key: "GET /api/groups/pit/verify", Summary: "Recompute a day's digest root", Tag: "history", Query: pairs("day:YYYY-MM-DD (default: the newest 100)")},
	{Key: "POST /api/groups/pit/rebuild", Summary: "Rebuild the point-in-time rows from the events", Tag: "history"},
	{Key: "POST /api/groups/engine/verify", Summary: "Recompute and repair the membership engine's tables", Tag: "engine"},
	{Key: "GET /api/groups/engine/ops/{seq}", Summary: "Progress of a queued recompute (the op of a 202 answer)", Tag: "engine"},
	// the attribute framework, object types and services (GR-7)
	{Key: "GET /api/groups/object-types", Summary: "The object type vocabulary of groups and folders", Tag: "attributes"},
	{Key: "GET /api/groups/services", Summary: "The services whose policy groups the caller belongs to", Tag: "attributes"},
	{Key: "GET /api/groups/{id}/object-types", Summary: "The object types of a group, with the lint findings", Tag: "attributes"},
	{Key: "PUT /api/groups/{id}/object-types", Summary: "Replace the object types of a group", Tag: "attributes"},
	{Key: "GET /api/groups/folders/{id}/object-types", Summary: "The object types of a folder", Tag: "attributes"},
	{Key: "PUT /api/groups/folders/{id}/object-types", Summary: "Replace the object types of a folder", Tag: "attributes"},
	{Key: "GET /api/groups/attr-defs", Summary: "List the attribute definitions the caller may view", Tag: "attributes", Query: pairs(qPage)},
	{Key: "POST /api/groups/attr-defs", Summary: "Create an attribute definition", Tag: "attributes", Created: true},
	{Key: "GET /api/groups/attr-defs/{id}", Summary: "Get an attribute definition", Tag: "attributes"},
	{Key: "PATCH /api/groups/attr-defs/{id}", Summary: "Edit an attribute definition", Tag: "attributes"},
	{Key: "DELETE /api/groups/attr-defs/{id}", Summary: "Delete an attribute definition and its assignments", Tag: "attributes"},
	{Key: "GET /api/groups/attr-defs/{id}/actions", Summary: "List the actions of a definition", Tag: "attributes"},
	{Key: "POST /api/groups/attr-defs/{id}/actions", Summary: "Add an action to a definition", Tag: "attributes", Created: true},
	{Key: "DELETE /api/groups/attr-defs/{id}/actions/{action_id}", Summary: "Remove an action", Tag: "attributes"},
	{Key: "PUT /api/groups/attr-defs/{id}/actions/{action_id}/implies", Summary: "Set the actions an action implies", Tag: "attributes"},
	{Key: "GET /api/groups/attr-defs/{id}/privileges", Summary: "List the privileges granted on an attribute definition", Tag: "privileges"},
	{Key: "POST /api/groups/attr-defs/{id}/privileges", Summary: "Grant a privilege on an attribute definition", Tag: "privileges", Body: "PrivilegeGrant", Created: true},
	{Key: "GET /api/groups/attr-defs/{id}/privileges/effective", Summary: "Explain the privileges an identity holds on an attribute definition", Tag: "privileges", Query: pairs(idQ)},
	{Key: "DELETE /api/groups/attr-defs/{id}/privileges/{privilege_id}", Summary: "Revoke one privilege row on an attribute definition", Tag: "privileges"},
	{Key: "GET /api/groups/attr-names", Summary: "List the attribute names the caller may view", Tag: "attributes", Query: pairs(qPage)},
	{Key: "POST /api/groups/attr-names", Summary: "Create an attribute name", Tag: "attributes", Created: true},
	{Key: "GET /api/groups/attr-names/{id}", Summary: "Get an attribute name", Tag: "attributes"},
	{Key: "PATCH /api/groups/attr-names/{id}", Summary: "Edit an attribute name", Tag: "attributes"},
	{Key: "DELETE /api/groups/attr-names/{id}", Summary: "Delete an attribute name", Tag: "attributes"},
	{Key: "PUT /api/groups/attr-names/{id}/implies", Summary: "Set the names a name implies", Tag: "attributes"},
	{Key: "GET /api/groups/attr-assignments", Summary: "List attribute assignments on an owner, or the names it has by implication", Tag: "attributes",
		Query: pairs("owner_type:folder, group, identity, membership, attr_def or assignment|owner:the owner's id|def:definition|name:attribute name|effective:true to include implied names|" + qPage)},
	{Key: "POST /api/groups/attr-assignments", Summary: "Assign an attribute name with an action to an owner", Tag: "attributes", Created: true},
	{Key: "GET /api/groups/attr-assignments/{id}", Summary: "Get an attribute assignment", Tag: "attributes"},
	{Key: "PATCH /api/groups/attr-assignments/{id}", Summary: "Change the dates of an assignment", Tag: "attributes"},
	{Key: "DELETE /api/groups/attr-assignments/{id}", Summary: "Remove an assignment and the ones on it", Tag: "attributes"},
	{Key: "PUT /api/groups/attr-assignments/{id}/values", Summary: "Replace the values of an assignment", Tag: "attributes"},
	{Key: "GET /api/groups/loaders", Summary: "List the loaders whose target folder the caller may view, with their job status", Tag: "loaders", Query: pairs(qPage)},
	{Key: "POST /api/groups/loaders", Summary: "Create a loader (a SQL loader needs a second admin's approval)", Tag: "loaders", Body: "LoaderSpec",
		Created: true, Approval: true},
	{Key: "GET /api/groups/loaders/{id}", Summary: "Get a loader (its definition needs stem_admin on its folder)", Tag: "loaders"},
	{Key: "PATCH /api/groups/loaders/{id}", Summary: "Change a loader (a SQL loader needs a second admin's approval, except turning it off)", Tag: "loaders",
		Body: "LoaderSpec", Approval: true},
	{Key: "POST /api/groups/loaders/{id}/run", Summary: "Run a loader now: full, incremental or a preview that applies nothing", Tag: "loaders", Body: "LoaderRunRequest"},
	{Key: "GET /api/groups/loaders/{id}/runs", Summary: "A loader's runs, newest first", Tag: "loaders", Query: pairs(qPage)},
	{Key: "GET /api/groups/loaders/{id}/runs/{run_id}", Summary: "One run, with its plan and downstream impact", Tag: "loaders"},
	{Key: "POST /api/groups/loaders/{id}/runs/{run_id}/approve", Summary: "Apply a held run as it was computed", Tag: "loaders"},
	{Key: "POST /api/groups/loaders/{id}/runs/{run_id}/reject", Summary: "Discard a held run", Tag: "loaders"},
	{Key: "GET /api/groups/loaders/{id}/unresolved", Summary: "Subjects the source named that match no identity", Tag: "loaders", Query: pairs(qPage)},
	{Key: "GET /api/groups/loader-tasks", Summary: "Inbox tasks of type loader_held: the runs a failsafe is holding", Tag: "loaders", Query: pairs(qPage)},
	{Key: "GET /scim/v2/Groups", Summary: "SCIM: list the groups the caller may view, with their effective members", Tag: "scim", Query: pairs(qScim)},
	{Key: "GET /scim/v2/Groups/{id}", Summary: "SCIM: one group", Tag: "scim", Query: pairs("excludedAttributes:attributes to leave out|attributes:attributes to return")},
	{Key: "GET /scim/v2/Users", Summary: "SCIM: list identities as users", Tag: "scim", Query: pairs(qScim)},
	{Key: "GET /scim/v2/Users/{id}", Summary: "SCIM: one identity, with the groups the caller may view", Tag: "scim",
		Query: pairs("excludedAttributes:attributes to leave out|attributes:attributes to return")},
	{Key: "GET /scim/v2/ServiceProviderConfig", Summary: "SCIM: what the server supports", Tag: "scim"},
	{Key: "GET /scim/v2/ResourceTypes", Summary: "SCIM: the resource types", Tag: "scim"},
	{Key: "GET /api/groups/event-sinks", Summary: "List the event sinks", Tag: "event-sinks"},
	{Key: "POST /api/groups/event-sinks", Summary: "Create an event sink", Tag: "event-sinks"},
	{Key: "GET /api/groups/event-sinks/{id}", Summary: "Get an event sink", Tag: "event-sinks"},
	{Key: "PATCH /api/groups/event-sinks/{id}", Summary: "Change an event sink", Tag: "event-sinks"},
	{Key: "DELETE /api/groups/event-sinks/{id}", Summary: "Delete an event sink", Tag: "event-sinks"},
	{Key: "GET /api/groups/event-sinks/{id}/dead-letters", Summary: "List the dead letters of a sink", Tag: "event-sinks"},
	{Key: "POST /api/groups/event-sinks/{id}/dead-letters/{seq}/redeliver", Summary: "Deliver a dead letter again", Tag: "event-sinks"},
	{Key: "POST /api/groups/event-sinks/{id}/dead-letters/{seq}/discard", Summary: "Discard a dead letter", Tag: "event-sinks"},
	{Key: "GET /api/groups/{id}/attestation", Summary: "Read id/attestation", Tag: "attestation"},
	{Key: "PUT /api/groups/{id}/attestation", Summary: "Save id/attestation", Tag: "attestation"},
	{Key: "DELETE /api/groups/{id}/attestation", Summary: "Delete id/attestation", Tag: "attestation"},
	{Key: "GET /api/groups/folders/{id}/attestation", Summary: "Read folders/id/attestation", Tag: "attestation"},
	{Key: "PUT /api/groups/folders/{id}/attestation", Summary: "Save folders/id/attestation", Tag: "attestation"},
	{Key: "DELETE /api/groups/folders/{id}/attestation", Summary: "Delete folders/id/attestation", Tag: "attestation"},
	{Key: "GET /api/groups/{id}/attestation/campaigns", Summary: "Read id/attestation/campaigns", Tag: "attestation"},
	{Key: "POST /api/groups/{id}/attestation/campaigns", Summary: "Create id/attestation/campaigns", Tag: "attestation"},
	{Key: "GET /api/groups/attestation/campaigns/{campaign_id}", Summary: "Read attestation/campaigns/campaign_id", Tag: "attestation"},
	{Key: "POST /api/groups/attestation/campaigns/{campaign_id}/items/{item_id}/decision", Summary: "Create attestation/campaigns/campaign_id/items/item_id/decision", Tag: "attestation"},
	{Key: "GET /api/groups/inbox/tasks", Summary: "Read inbox/tasks", Tag: "inbox"},
	{Key: "POST /api/groups/inbox/tasks/{task_id}/close", Summary: "Create inbox/tasks/task_id/close", Tag: "inbox"},
	{Key: "GET /api/groups/deprovisioning/settings", Summary: "Read deprovisioning/settings", Tag: "deprovisioning"},
	{Key: "PUT /api/groups/deprovisioning/settings", Summary: "Save deprovisioning/settings", Tag: "deprovisioning"},
	{Key: "GET /api/groups/folders/{id}/deprovisioning", Summary: "Read folders/id/deprovisioning", Tag: "deprovisioning"},
	{Key: "PUT /api/groups/folders/{id}/deprovisioning", Summary: "Save folders/id/deprovisioning", Tag: "deprovisioning"},
	{Key: "DELETE /api/groups/folders/{id}/deprovisioning", Summary: "Delete folders/id/deprovisioning", Tag: "deprovisioning"},
	{Key: "GET /api/groups/deprovisioning/items", Summary: "Read deprovisioning/items", Tag: "deprovisioning"},
	{Key: "POST /api/groups/deprovisioning/items/{item_id}/resolve", Summary: "Create deprovisioning/items/item_id/resolve", Tag: "deprovisioning"},
	{Key: "GET /api/groups/reports/catalogue", Summary: "Read reports/catalogue", Tag: "reports"},
	{Key: "GET /api/groups/reports/saved", Summary: "Read reports/saved", Tag: "reports"},
	{Key: "POST /api/groups/reports/saved", Summary: "Create reports/saved", Tag: "reports"},
	{Key: "GET /api/groups/reports/saved/{report_id}", Summary: "Read reports/saved/report_id", Tag: "reports"},
	{Key: "PUT /api/groups/reports/saved/{report_id}", Summary: "Save reports/saved/report_id", Tag: "reports"},
	{Key: "DELETE /api/groups/reports/saved/{report_id}", Summary: "Delete reports/saved/report_id", Tag: "reports"},
	{Key: "POST /api/groups/reports/saved/{report_id}/run", Summary: "Create reports/saved/report_id/run", Tag: "reports"},
	{Key: "GET /api/groups/reports/saved/{report_id}/runs", Summary: "Read reports/saved/report_id/runs", Tag: "reports"},
	{Key: "GET /api/groups/reports/runs/{run_id}", Summary: "Read reports/runs/run_id", Tag: "reports"},
	{Key: "POST /api/groups/reports/run", Summary: "Create reports/run", Tag: "reports"},
	{Key: "GET /api/groups/{id}/graph", Summary: "Read id/graph", Tag: "graph"},
	{Key: "GET /api/groups/graph/identity/{identity_id}", Summary: "Read graph/identity/identity_id", Tag: "graph"},
	{Key: "POST /api/groups/policy/validate", Summary: "Validate policy group files", Tag: "policy"},
	{Key: "POST /api/groups/policy/diff", Summary: "Diff policy group files against the groups", Tag: "policy"},
	{Key: "POST /api/groups/policy/apply", Summary: "Apply policy group files", Tag: "policy"},
	{Key: "POST /api/groups/policy/reindex", Summary: "Rebuild the policy index", Tag: "policy"},
	{Key: "GET /api/groups/{id}/policy", Summary: "The policy source of a group", Tag: "policy"},
	{Key: "GET /api/groups/folders/{id}/rules", Summary: "List the rules of a folder", Tag: "rules"},
	{Key: "POST /api/groups/folders/{id}/rules", Summary: "Create a folder rule", Tag: "rules"},
	{Key: "PUT /api/groups/folders/{id}/rules/{rule_id}", Summary: "Replace a folder rule", Tag: "rules"},
	{Key: "DELETE /api/groups/folders/{id}/rules/{rule_id}", Summary: "Delete a folder rule", Tag: "rules"},
	{Key: "GET /api/groups/{id}/rules", Summary: "List the rules of a group", Tag: "rules"},
	{Key: "POST /api/groups/{id}/rules", Summary: "Create a group rule", Tag: "rules"},
	{Key: "PUT /api/groups/{id}/rules/{rule_id}", Summary: "Replace a group rule", Tag: "rules"},
	{Key: "DELETE /api/groups/{id}/rules/{rule_id}", Summary: "Delete a group rule", Tag: "rules"},
	{Key: "GET /api/groups/rules/settings", Summary: "Read the tenant's rule settings", Tag: "rules"},
	{Key: "PUT /api/groups/rules/settings", Summary: "Save the tenant's rule settings", Tag: "rules"},
}

var docs = func() map[string]opDoc {
	m := make(map[string]opDoc, len(docList))
	for _, d := range docList {
		m[d.Key] = d
	}
	return m
}()

// pairs splits "a:b|c:d" into ["a:b", "c:d"].
func pairs(s string) []string { return strings.Split(s, "|") }

// Documented lists the routes the document describes ("METHOD pattern").
func Documented() []string {
	out := make([]string, 0, len(docs))
	for k := range docs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func pathParams(pattern string) []string {
	var out []string
	for _, seg := range strings.Split(pattern, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			out = append(out, seg[1:len(seg)-1])
		}
	}
	return out
}

type obj = map[string]any

func errResp(desc string) obj {
	return obj{"description": desc, "content": obj{"application/json": obj{"schema": obj{"$ref": "#/components/schemas/Error"}}}}
}

func param(in, name, desc string, required bool) obj {
	p := obj{"name": name, "in": in, "required": required, "schema": obj{"type": "string"}}
	if desc != "" {
		p["description"] = desc
	}
	return p
}

// OpenAPI builds the document of the routes it covers. cookie is the session
// cookie's name. A covered route without an entry in docs is left out; the
// caller's test fails on it.
func OpenAPI(routes []RouteInfo, cookie string) ([]byte, error) {
	paths := obj{}
	for _, rt := range routes {
		d, ok := docs[rt.Method+" "+rt.Pattern]
		if !ok || !Covers(rt.Method, rt.Pattern) {
			continue
		}
		item, _ := paths[rt.Pattern].(obj)
		if item == nil {
			item = obj{}
			paths[rt.Pattern] = item
		}
		var params []obj
		for _, p := range pathParams(rt.Pattern) {
			params = append(params, param("path", p, "", true))
		}
		for _, q := range d.Query {
			name, desc, _ := strings.Cut(q, ":")
			params = append(params, param("query", name, desc, false))
		}
		for _, h := range d.Header {
			name, desc, _ := strings.Cut(h, ":")
			params = append(params, param("header", name, desc, false))
		}
		okCode := "200"
		if d.Created {
			okCode = "201"
		}
		body := obj{"description": "Success"}
		if d.Result != "" {
			body["content"] = obj{"application/json": obj{"schema": obj{"$ref": "#/components/schemas/" + d.Result}}}
		}
		resp := obj{okCode: body, "401": errResp("Not signed in"),
			"403": errResp("Missing the route's permission (forbidden) or the object's privilege (privilege_required)"),
			"404": errResp("No such object"), "409": errResp("A name, state or cycle conflict"), "422": errResp("Invalid input")}
		if d.Accepted {
			resp["202"] = obj{"description": "The change is committed and the recompute is queued; op names the operation (GET /api/groups/engine/ops/{seq})"}
		}
		if d.Approval {
			resp["202"] = obj{"description": "The loader runs a SQL query, so the change is not applied: change_request_id names the " +
				"groups.loader.save request a second admin approves (POST /api/admin/change-requests/{id}/approve)"}
		}
		if strings.HasPrefix(rt.Pattern, "/api/groups/loader") {
			resp["502"] = errResp("A run could not read its source or apply its plan (loader_run_failed; the run is in the body)")
		}
		if strings.HasPrefix(rt.Pattern, "/scim/") {
			resp["400"] = obj{"description": "Invalid filter (scimType invalidFilter)"}
		}
		op := obj{"summary": d.Summary, "tags": []string{d.Tag}, "operationId": opID(rt.Method, rt.Pattern), "responses": resp,
			"x-tessera-permission": rt.Perm, "x-tessera-step-up": rt.StepUp}
		if len(params) > 0 {
			op["parameters"] = params
		}
		switch {
		case d.Body != "":
			op["requestBody"] = obj{"required": true, "content": obj{"application/json": obj{"schema": obj{"$ref": "#/components/schemas/" + d.Body}}}}
		case rt.Method == "POST" || rt.Method == "PUT" || rt.Method == "PATCH":
			op["requestBody"] = obj{"required": false, "content": obj{"application/json": obj{"schema": obj{"type": "object"}}}}
		}
		item[strings.ToLower(rt.Method)] = op
	}
	doc := obj{
		"openapi": "3.1.0",
		"info": obj{"title": "Tessera groups API", "version": "0.1.0",
			"description": "Native groups (design docs/design/groups-grouper-parity.md §10.11), generated from the server's route table. " +
				"Every route needs its permission (x-tessera-permission) and then the privilege of the folder or group it names (403 privilege_required). " +
				"Errors are {\"error\": code, \"detail\": message}; SCIM errors follow RFC 7644. Writes accept Idempotency-Key."},
		"paths":      paths,
		"components": obj{"schemas": schemas(), "securitySchemes": obj{"session": obj{"type": "apiKey", "in": "cookie", "name": cookie}}},
		"security":   []obj{{"session": []string{}}},
	}
	return json.MarshalIndent(doc, "", " ")
}

func opID(method, pattern string) string {
	r := strings.NewReplacer("/", "_", "{", "", "}", "", ":", "_", "-", "_", ".", "_")
	return strings.ToLower(method) + r.Replace(pattern)
}

func schemas() obj {
	str := obj{"type": "string"}
	integer := obj{"type": "integer"}
	boolean := obj{"type": "boolean"}
	arr := func(items obj) obj { return obj{"type": "array", "items": items} }
	object := obj{"type": "object"}
	return obj{
		"Error": obj{"type": "object", "properties": obj{"error": str, "detail": str}, "required": []string{"error"}},
		"PrivilegeGrant": obj{"type": "object", "required": []string{"privilege", "holder_type"}, "properties": obj{"privilege": str,
			"holder_type": obj{"enum": []string{"identity", "group", "everyone"}}, "identity": integer, "group": str, "applies_to": str, "scope": str}},
		"MemberPage": obj{"type": "object", "properties": obj{"items": arr(object), "limit": integer, "offset": integer, "total": integer,
			"filter": str, "stale": boolean}},
		"GroupPage": obj{"type": "object", "properties": obj{"identity_id": integer, "items": arr(object), "limit": integer, "offset": integer,
			"total": integer, "filter": str}},
		"MemberTrace": obj{"type": "object", "properties": obj{"group_id": str, "identity_id": integer, "member": boolean, "stale": boolean,
			"paths": arr(obj{"type": "object", "properties": obj{"steps": arr(obj{"type": "object", "properties": obj{"group_id": str, "name": str,
				"via": obj{"enum": []string{"start", "nested", "factor"}}, "op": str, "role": str}})}}), "truncated": boolean}},
		"LoaderSpec": obj{"type": "object", "required": []string{"name", "type", "config", "target_folder"}, "properties": obj{"name": str,
			"type":          obj{"enum": []string{"sql_simple", "sql_group_list", "csv", "connector_groups", "attribute", "recent_memberships", "scim", "ldap_simple", "ldap_group_list"}},
			"connection_id": str, "config": object, "target_folder": str, "name_template": str,
			"on_missing_group": obj{"enum": []string{"empty", "disable", "delete", "keep"}}, "and_group": str,
			"schedule":         obj{"type": "string", "description": "five-field cron in UTC, or @hourly, @daily, @weekly (default @daily)"},
			"incremental_secs": integer, "failsafe": object, "status": obj{"enum": []string{"enabled", "disabled"}},
			"secret": obj{"type": "string", "writeOnly": true, "description": "the credential: a csv url's bearer token, a scim provider's bearer token or client secret, an ldap bind password, or the postgres:// connection string of a SQL loader with engine postgres; sealed, never returned"}}},
		"LoaderRunRequest": obj{"type": "object", "properties": obj{"kind": obj{"enum": []string{"full", "incremental", "preview"}, "default": "full"}}},
		"BatchRequest": obj{"type": "object", "properties": obj{
			"add":    arr(obj{"type": "object", "properties": obj{"identity": integer, "group": str, "enabled_from": str, "disabled_at": str, "reason": str}}),
			"remove": arr(str), "enabled_from": str, "disabled_at": str, "reason": str,
			"atomic": obj{"type": "boolean", "default": true, "description": "false: each operation stands or falls by itself and failures are reported in results"}}},
		"BatchResponse": obj{"type": "object", "properties": obj{"group_id": str, "atomic": boolean, "created": integer, "updated": integer,
			"removed": integer, "failed": integer, "effective": obj{"enum": []string{"applied", "pending"}}, "ops": arr(integer),
			"results": arr(obj{"type": "object", "properties": obj{"index": integer, "op": str, "member_type": str, "member": str,
				"status": obj{"enum": []string{"created", "updated", "removed", "failed"}}, "effective": str, "op_id": integer,
				"error": obj{"$ref": "#/components/schemas/Error"}}})}},
		"SimulateRequest": obj{"type": "object", "required": []string{"changes"}, "properties": obj{"changes": arr(obj{"type": "object", "properties": obj{
			"kind": obj{"enum": []string{"add_member", "remove_member", "set_composite", "convert_to_composite"}}, "group": str, "identity": integer,
			"member_group": str, "member": str, "enabled_from": str, "disabled_at": str, "reason": str, "op": str, "factors": arr(str),
			"discard_members": boolean}})}},
		"SimulateResponse": obj{"type": "object", "properties": obj{"simulated": boolean, "changes": arr(object),
			"groups": arr(obj{"type": "object", "properties": obj{"group_id": str, "name": str, "targeted": boolean, "before": integer,
				"after": integer, "added": integer, "removed": integer, "added_sample": arr(object), "removed_sample": arr(object)}}),
			"added": integer, "removed": integer, "truncated": boolean}},
	}
}
