import { useState } from "react";
import { Copy, Download } from "lucide-react";
import { ApiClient, downloadApiSpec, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, DataTable, Page, useToast } from "../../components";
import { errText } from "./common";

/**
 * API developer: what a customer needs to call the Tessera API as a machine client. The clients
 * and their scopes are read-only here (register, re-key and revoke them under API clients, which
 * files the change for a fresh passkey sign-in); the OpenAPI document describes every route with
 * the permission and scopes it needs; the examples show the token flow.
 */
export function ApiDeveloper() {
  const { session } = useSession();
  const { data, error, reload } = useApi<ApiClient[]>("/admin/api-clients");
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const origin = window.location.origin;
  const slug = session.tenant.slug;
  const machines = data ? data.filter((c) => c.kind === "machine") : null;

  const download = async () => {
    setBusy(true);
    try {
      await downloadApiSpec();
      toast("OpenAPI document saved");
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Page
      title="API developer"
      crumbs={[["Settings"], ["Admin", "/admin"], ["API developer"]]}
      sub="Call the API as a machine client: get a short-lived token with the client credentials grant, then send it with each request. Every request is audited and rate limited per client."
    >
      <div className="stack">
        <div className="row">
          <Button icon={<Download size={14} />} onClick={download} disabled={busy}>Download OpenAPI document</Button>
          <a className="small" href="/docs" target="_blank" rel="noreferrer">Open Swagger UI</a>
          <a className="small" href="/api/openapi.json" target="_blank" rel="noreferrer">View the JSON</a>
        </div>
        <p className="small faint" style={{ margin: 0 }}>
          The document is OpenAPI 3.1 and lists every route with its parameters, error codes, the permission it needs and the token scopes that grant it.
          Stable integrations use the <code>/api/v1</code> prefix; the same routes under <code>/api</code> serve the admin console and may change with it.
        </p>

        <DataTable
          id="api-developer-clients"
          rows={machines}
          error={error}
          rowKey={(c) => c.client_id}
          onRefresh={reload}
          rowLabel={(c) => c.name}
          columns={[
            { id: "name", header: "Machine client", sort: (c) => c.name, cell: (c) => <div><b>{c.name}</b><div className="xs faint"><code>{c.client_id}</code></div></div> },
            { id: "scopes", header: "Scopes", cell: (c) => <span className="small">{c.allowed_scopes.length ? c.allowed_scopes.join(", ") : "—"}</span> },
            { id: "roles", header: "Roles", hideNarrow: true, cell: (c) => <span className="small">{c.roles.length ? c.roles.join(", ") : "—"}</span> },
            { id: "dpop", header: "Token", hideNarrow: true, cell: (c) => <span className="small">{c.dpop_required ? "DPoP-bound" : "Bearer"}</span> },
            { id: "status", header: "Status", sort: (c) => c.status, cell: (c) => (c.status === "active" ? <Badge tone="ok" dot>Active</Badge> : <Badge tone="neutral" dot>Revoked</Badge>) },
          ]}
          searchText={(c) => `${c.name} ${c.client_id} ${c.allowed_scopes.join(" ")} ${c.roles.join(" ")}`}
          searchPlaceholder="Search machine clients…"
          empty="No machine clients yet."
        />
        <p className="small faint" style={{ margin: 0 }}>
          A client can do what its roles allow <b>and</b> its scopes grant. To register one with a public key, re-key or revoke it, go to <a href="/admin/api-clients">API clients</a>.
        </p>

        <h2 className="h3" style={{ margin: "8px 0 0" }}>Token flow</h2>
        <Callout tone="info">
          The client signs a short assertion (a JWT, <code>private_key_jwt</code>) with its private key. Tessera never sees the key. Replace the placeholders in capitals.
        </Callout>
        <Example
          title="1. Get an access token"
          code={`curl -s -X POST ${origin}/t/${slug}/oauth/token \\
  -d grant_type=client_credentials \\
  -d client_id=CLIENT_ID \\
  -d scope="tessera:read" \\
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \\
  -d client_assertion="$ASSERTION"`}
        />
        <Example
          title="2. Call a route (DPoP-bound client)"
          code={`curl -s ${origin}/api/v1/summary \\
  -H "Authorization: DPoP $ACCESS_TOKEN" \\
  -H "DPoP: $DPOP_PROOF"`}
        />
        <Example
          title="2. Call a route (client that is not DPoP-required)"
          code={`curl -s "${origin}/api/v1/identities?limit=50" \\
  -H "Authorization: Bearer $ACCESS_TOKEN"`}
        />
        <Example
          title="Next page of a list"
          code={`curl -s "${origin}/api/v1/identities?limit=50&cursor=$NEXT_CURSOR" \\
  -H "Authorization: Bearer $ACCESS_TOKEN"`}
        />
        <p className="small faint" style={{ margin: 0 }}>
          Metadata: <code>{origin}/t/{slug}/.well-known/oauth-authorization-server</code>. Answers carry <code>RateLimit-Limit</code>, <code>RateLimit-Remaining</code> and <code>RateLimit-Reset</code>;
          over the limit a request gets <code>429</code> with <code>Retry-After</code>.
        </p>
      </div>
    </Page>
  );
}

function Example({ title, code }: { title: string; code: string }) {
  const toast = useToast();
  return (
    <div className="stack-sm">
      <div className="row tight">
        <b className="small">{title}</b>
        <Button
          size="sm"
          icon={<Copy size={13} />}
          onClick={() => navigator.clipboard?.writeText(code).then(() => toast("Copied"), () => toast("Copy failed: select the text and copy it", { kind: "error" }))}
        >
          Copy
        </Button>
      </div>
      <pre className="code" tabIndex={0} aria-label={title} style={{ margin: 0, overflowX: "auto", padding: 12, background: "var(--surface-2, #f4f5f7)", borderRadius: 6, fontSize: 12 }}>{code}</pre>
    </div>
  );
}
