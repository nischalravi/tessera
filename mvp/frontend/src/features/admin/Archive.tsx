import { useState } from "react";
import { Download, ShieldCheck } from "lucide-react";
import { ArchiveList, ArchiveSegment, SegmentCheck, archive, downloadArchiveSegment, fmtDate, useApi } from "../../api";
import { useSession } from "../../app/auth";
import { Badge, Button, Callout, DataTable, SidePanel, useToast } from "../../components";
import { Fact, errText } from "./common";
import { CLASS_LABEL, SEGMENT_LABEL, SEGMENT_TONE, exportName, fmtBytes, rangeLabel } from "./retentionModel";

const when = (s: string | null) => (s ? fmtDate(s.replace("Z", "")) : "—");

/**
 * Admin → Archive (issue #298): the sealed segments of records that passed their retention (Admin → Retention).
 * An admin can verify a segment (it is read back from the archive store and checked; an audit segment's
 * hash chain is recomputed) and export it as NDJSON, the read-only restore: nothing is written back online.
 */
export function Archive() {
  const { data, error, reload } = useApi<ArchiveList>("/admin/archive/segments?limit=500");
  const [open, setOpen] = useState<ArchiveSegment | null>(null);
  const rows = data?.segments ?? null;
  return (
    <div className="stack">
      {data && !data.archive.enabled && (
        <Callout tone="warn">
          Archiving is not configured on this server, so there is nothing new to list and a segment below cannot be read back. Set <code>TESSERA_ARCHIVE_DIR</code> or <code>TESSERA_ARCHIVE_URL</code>.
        </Callout>
      )}
      <DataTable
        id="archive-segments"
        rows={rows}
        error={error}
        onRefresh={reload}
        rowKey={(g) => g.id}
        initialSort={["created", -1]}
        onRowClick={setOpen}
        activeKey={open?.id}
        rowLabel={(g) => `${CLASS_LABEL[g.class]} ${rangeLabel(g)}`}
        columns={[
          { id: "class", header: "Records", sort: (g) => g.class, cell: (g) => <b>{CLASS_LABEL[g.class] ?? g.class}</b> },
          { id: "range", header: "Covers", csv: (g) => rangeLabel(g), cell: (g) => <span className="small">{rangeLabel(g)}</span> },
          { id: "count", header: "Records", num: true, sort: (g) => g.count, cell: (g) => <span className="small tnum">{g.count}</span> },
          { id: "status", header: "State", sort: (g) => g.status, cell: (g) => <Badge tone={SEGMENT_TONE[g.status]} dot>{SEGMENT_LABEL[g.status]}</Badge> },
          { id: "size", header: "Size", num: true, hideNarrow: true, sort: (g) => g.size_bytes, cell: (g) => <span className="small tnum">{fmtBytes(g.size_bytes)}</span> },
          { id: "created", header: "Archived", hideNarrow: true, sort: (g) => g.created_at, cell: (g) => <span className="small nowrap">{when(g.created_at)}</span> },
        ]}
        searchText={(g) => `${CLASS_LABEL[g.class]} ${g.class} ${g.status} ${rangeLabel(g)} ${g.id}`}
        searchPlaceholder="Search records, range or segment id…"
        chips={2}
        filters={[
          { id: "class", label: "Records", options: Object.entries(CLASS_LABEL).map(([value, label]) => ({ value, label })), get: (g) => g.class },
          { id: "status", label: "State", options: Object.entries(SEGMENT_LABEL).map(([value, label]) => ({ value, label })), get: (g) => g.status },
        ]}
        empty="Nothing has been archived yet. Records move here when they pass the time set in Retention."
      />
      {open && <SegmentPanel segment={open} onClose={() => setOpen(null)} />}
    </div>
  );
}

function SegmentPanel({ segment: g, onClose }: { segment: ArchiveSegment; onClose: () => void }) {
  const toast = useToast();
  const { can } = useSession();
  const [busy, setBusy] = useState<"verify" | "export" | null>(null);
  const [result, setResult] = useState<SegmentCheck | null>(null);
  const usable = g.status !== "failed";

  const verify = async () => {
    setBusy("verify");
    setResult(null);
    try {
      setResult(await archive.verify(g.id));
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(null);
    }
  };
  const exportIt = async () => {
    setBusy("export");
    try {
      const blob = await downloadArchiveSegment(g.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = exportName(g);
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast("Exported: the records are in the file, read-only. Nothing was restored online.");
    } catch (e) {
      toast(errText(e), { kind: "error" });
    } finally {
      setBusy(null);
    }
  };

  return (
    <SidePanel
      title={CLASS_LABEL[g.class] ?? g.class}
      sub={<span className="row tight"><Badge tone={SEGMENT_TONE[g.status]} dot>{SEGMENT_LABEL[g.status]}</Badge> <span className="small faint">{rangeLabel(g)}</span></span>}
      onClose={onClose}
      commands={
        <>
          {can("audit.verify") && <Button size="sm" icon={<ShieldCheck size={13} />} disabled={!usable || busy !== null} onClick={verify}>Verify</Button>}
          {can("audit.read") && <Button size="sm" variant="primary" icon={<Download size={13} />} disabled={!usable || busy !== null} onClick={exportIt}>Export</Button>}
        </>
      }
    >
      <div className="stack-sm">
        {g.status === "failed" && (
          <Callout tone="bad">This segment failed verification when it was written, so it was given up. Its records stayed online and were archived again in a newer segment.</Callout>
        )}
        {result && (
          result.ok ? (
            <Callout tone="ok">
              <b>Verified {fmtDate(result.checked_at.replace("Z", ""))}.</b> {result.records} records read back from the archive store.
              <ul className="small" style={{ margin: "4px 0 0", paddingLeft: 18 }}>{(result.checks ?? []).map((c) => <li key={c}>{c}</li>)}</ul>
            </Callout>
          ) : (
            <Callout tone="bad"><b>This segment does not verify.</b> {result.problem}</Callout>
          )
        )}
        <dl className="kv small">
          <dt>Records</dt><dd>{g.count}</dd>
          <dt>Covers</dt><dd>{rangeLabel(g)}</dd>
          <dt>Archived</dt><dd>{when(g.created_at)}</dd>
          <dt>Verified</dt><dd>{when(g.verified_at)}</dd>
          <dt>Removed online</dt><dd>{when(g.purged_at)}</dd>
          <dt>Stored</dt><dd>{g.location === "remote" ? "Object store" : "Local directory"}, {fmtBytes(g.size_bytes)}, sealed under the key-encryption key</dd>
          <dt>Checksum</dt><dd><code className="xs" style={{ wordBreak: "break-all" }}>{g.sha256}</code></dd>
          <dt>Segment id</dt><dd><code className="xs">{g.id}</code></dd>
        </dl>
        {g.class === "audit" && g.first_hash && g.last_hash && (
          <div className="stack-sm">
            <Fact label="First event hash"><code className="xs" style={{ wordBreak: "break-all" }}>{g.first_hash}</code></Fact>
            <Fact label="Last event hash"><code className="xs" style={{ wordBreak: "break-all" }}>{g.last_hash}</code></Fact>
            <p className="small muted" style={{ margin: 0 }}>
              The online audit chain continues from the last hash above and records an “archived up to {g.seq_to}” event, so Verify in the audit log checks the archived events too.
            </p>
          </div>
        )}
        <p className="small muted" style={{ margin: 0 }}>Export streams the records as NDJSON after checking them; it needs a fresh passkey sign-in and is recorded in the audit log.</p>
      </div>
    </SidePanel>
  );
}
