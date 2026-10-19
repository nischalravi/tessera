import { AdminApiClients, useApi } from "../../api";
import { Callout, DataTable, Page } from "../../components";

/**
 * Machine clients (design §9.5). The list comes from GET /api/admin/api-clients, which is empty and
 * says why until the OAuth authorization server and machine clients land (PR10, PR11); this page
 * needs no change when they do.
 */
export function ApiClients() {
  const { data, error, reload } = useApi<AdminApiClients>("/admin/api-clients");
  return (
    <Page
      title="API clients"
      crumbs={[["Settings"], ["Admin", "/admin"], ["API clients"]]}
      sub="Machines and automation that call the Tessera API with short-lived, sender-constrained tokens. Creating a client, rotating its key or granting it audit scope will be admin changes; the admin scope is never granted to a machine."
    >
      <div className="stack">
        {data && !data.available && <Callout tone="neutral">{data.detail}.</Callout>}
        <DataTable
          id="admin-api-clients"
          rows={data ? data.clients : null}
          error={error}
          rowKey={(c) => c.id}
          onRefresh={reload}
          columns={[{ id: "name", header: "Client", sort: (c) => c.name, cell: (c) => <b>{c.name}</b> }]}
          searchText={(c) => c.name}
          searchPlaceholder="Search clients…"
          empty="No API clients."
        />
      </div>
    </Page>
  );
}
