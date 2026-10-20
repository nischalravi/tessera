import { Badge, Loading } from "../../components";
import { IdentityBundle, fmtDate, useApi } from "../../api";
import { BUNDLE_STATE_LABEL, BUNDLE_STATE_TONE } from "../access/guestModel";

/** The guest access bundles of a person with the state of each item (issue #75). */
export function BundleSection({ identityId }: { identityId: number }) {
  const { data, error } = useApi<IdentityBundle>(`/identities/${identityId}/access-bundle`);
  if (!data) return <Loading error={error} kind="block" />;
  return (
    <section className="stack-sm" aria-labelledby={`bundle-${identityId}`}>
      <h3 id={`bundle-${identityId}`} style={{ fontSize: "var(--fs-lg)", color: "var(--text)" }}>Guest access bundle</h3>
      <p className="xs faint">Identity assurance reached: IAL {data.ial}. Each item belongs to one sponsorship and ends with it.</p>
      {data.items.length === 0 ? <p className="muted small">No bundle items.</p> : (
        <table className="table">
          <thead><tr><th>Item</th><th>State</th><th>Expires</th></tr></thead>
          <tbody>
            {data.items.map((i) => (
              <tr key={i.id}>
                <td><b>{i.system}:{i.name}</b>{i.detail && <div className="xs faint">{i.detail}</div>}</td>
                <td><Badge tone={BUNDLE_STATE_TONE[i.state]}>{BUNDLE_STATE_LABEL[i.state]}</Badge></td>
                <td className="small nowrap">{fmtDate(i.expires_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
