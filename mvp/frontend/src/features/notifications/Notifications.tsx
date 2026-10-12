import { useState } from "react";
import { Link } from "react-router-dom";
import { Bell, CheckCheck } from "lucide-react";
import { NotificationChannel, NotificationKindPref, NotificationPrefs, fmtDate, markNotificationsRead, putNotificationPrefs, relTime, useApi } from "../../api";
import { Badge, Button, Callout, EmptyState, FilterChips, Loading, Page, useToast } from "../../components";
import { KIND_LABEL, useNotifications } from "./model";
import { useOpenNotification } from "./open";

const CHANNEL_LABEL: Record<NotificationChannel, string> = {
  off: "Off",
  in_app: "In Tessera only",
  email: "Email only",
  both: "In Tessera and email",
  digest: "In Tessera and a daily email digest",
};
const NEEDS_EMAIL: NotificationChannel[] = ["email", "both", "digest"];

/** Per-kind channel settings of the signed-in user. Changes save as you make them. */
export function NotificationPreferences() {
  const { data, error } = useApi<NotificationPrefs>("/notifications/preferences");
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  if (!data) return <Loading error={error} kind="block" />;
  const set = async (k: NotificationKindPref, channel: NotificationChannel) => {
    setBusy(k.kind);
    try {
      await putNotificationPrefs({ [k.kind]: channel });
      toast(`${k.label}: ${CHANNEL_LABEL[channel]}`);
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="card stack-sm">
      <h2 className="row tight"><Bell size={16} aria-hidden /> Your notification settings</h2>
      <p className="small muted" style={{ margin: 0 }}>
        Choose, for each kind of event, whether it shows in the bell, arrives by email, goes into one email a day, or is off. Changes save as you make them.
      </p>
      {!data.email_available && (
        <Callout tone="neutral">This server does not send email, so only the in-app choices have an effect. An administrator can turn email on with the TESSERA_SMTP_* settings.</Callout>
      )}
      {data.email_dev_sink && (
        <Callout tone="warn">Email goes to the development mail sink (a file on the server), not to real inboxes.</Callout>
      )}
      <div className="table-scroll">
        <table>
          <thead><tr><th>Event</th><th style={{ width: 280 }}>Notify me</th></tr></thead>
          <tbody>
            {data.kinds.map((k) => (
              <tr key={k.kind}>
                <td>
                  <label htmlFor={`pref-${k.kind}`}><b>{k.label}</b></label>
                  {k.mandatory && <> <Badge tone="info">Always on</Badge></>}
                  <div className="small faint">{k.description}</div>
                </td>
                <td>
                  <select id={`pref-${k.kind}`} className="input" style={{ width: "100%" }} value={k.channel} disabled={busy === k.kind}
                    onChange={(e) => set(k, e.target.value as NotificationChannel)}>
                    {data.channels.map((c) => (
                      <option key={c} value={c} disabled={(k.mandatory && c === "off") || (!data.email_available && NEEDS_EMAIL.includes(c))}>
                        {CHANNEL_LABEL[c]}{c === k.default ? " (default)" : ""}
                      </option>
                    ))}
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** The signed-in user's inbox and settings. */
export function Notifications() {
  const [filter, setFilter] = useState<"all" | "unread">("all");
  const { data, error, reload } = useNotifications();
  const open = useOpenNotification();
  const toast = useToast();
  const items = (data?.items ?? []).filter((n) => filter === "all" || !n.read_at);
  const markAll = async () => {
    try {
      await markNotificationsRead({ all: true });
      reload();
    } catch (e) {
      toast((e as Error).message, { kind: "error" });
    }
  };
  return (
    <Page title="Notifications" crumbs={[["Notifications"]]} count={data ? `${data.unread} unread` : undefined}
      sub="Requests, approvals, reviews and expiring access that need your attention."
      actions={<Button icon={<CheckCheck size={14} />} disabled={!data?.unread} onClick={markAll}>Mark all as read</Button>}>
      <div className="stack">
        <div className="card flush">
          <div className="card-h">
            <h2>Inbox</h2>
            <FilterChips label="Filter notifications" value={filter} onChange={setFilter}
              options={[{ id: "all", label: "All", count: data?.items.length }, { id: "unread", label: "Unread", count: data?.unread }]} />
          </div>
          {!data ? <div className="card-b"><Loading error={error} kind="block" /></div> : items.length === 0 ? (
            <EmptyState icon={<Bell size={20} />} title={filter === "unread" ? "No unread notifications" : "Nothing yet"}>
              When a request needs you, an access review starts or access is about to end, it shows up here.
            </EmptyState>
          ) : (
            <ul className="notif-list" aria-label="Notifications">
              {items.map((n) => (
                <li key={n.id}>
                  <button type="button" className={`notif-item ${n.read_at ? "" : "unread"}`} onClick={() => open(n)}>
                    <span className="notif-dot" aria-hidden />
                    <span className="grow">
                      <span className="row tight"><b>{n.subject}</b><span className="chip">{KIND_LABEL[n.kind] ?? n.kind}</span>{!n.read_at && <span className="sr-only">Unread</span>}</span>
                      <span className="small muted notif-body">{n.body}</span>
                      <span className="small faint" title={fmtDate(n.created_at)}>{relTime(n.created_at)}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
        <NotificationPreferences />
      </div>
    </Page>
  );
}

/** For the admin page: where users manage their own settings. */
export function NotificationsAdminPanel() {
  return (
    <div className="stack">
      <div className="card small">
        Notifications are live. Each person chooses what they get under <Link to="/notifications">Notifications</Link>; the settings below are yours.
      </div>
      <NotificationPreferences />
    </div>
  );
}
