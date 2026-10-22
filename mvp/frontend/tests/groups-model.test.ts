// Directory → Groups (GR-8): the pure logic behind the screens. The change preview, the trace, the folder
// browser, history, privileges and the new-application template. Run with `npm test`.
import assert from "node:assert/strict";
import { test } from "node:test";
import * as m from "../src/features/directory/groups/model.ts";

const folder = (id: string, name: string, parent: string | null) => ({
  id, parent_id: parent, extension: name.split(":").pop() ?? "", display_extension: "", name, display_name: name,
  description: "", data_owner: null, managed_by: "ui", created_at: "2026-10-01T00:00:00Z", version: 1,
});

test("names follow the server's rule", () => {
  assert.equal(m.extensionProblem("payroll_v2.prod-1"), null);
  assert.match(m.extensionProblem("")!, /name/);
  assert.match(m.extensionProblem("a:b")!, /not allowed/);
  assert.match(m.extensionProblem("a b")!, /not allowed/);
  assert.match(m.extensionProblem("..")!, /cannot be/);
  assert.match(m.extensionProblem("x".repeat(256))!, /255/);
});

test("the folder tree hides what the caller cannot see and keeps its place", () => {
  const all = [folder("r", "", null), folder("a", "app", "r"), folder("b", "app:foo", "a"), folder("c", "org", "r")];
  const ix = m.indexFolders(all);
  assert.equal(ix.root?.id, "r");
  assert.deepEqual(m.childFolders(ix, null).map((f) => f.name), ["app", "org"]);
  assert.deepEqual(m.childFolders(ix, "a").map((f) => f.name), ["app:foo"]);
  assert.deepEqual(m.folderTrail(ix, "b").map((f) => f.name), ["app", "app:foo"]);

  // a caller who may view only app:foo (not its parents or the root) still gets it as a top-level folder
  const partial = m.indexFolders([folder("b", "app:foo", "a")]);
  assert.equal(partial.root, null);
  assert.deepEqual(m.childFolders(partial, null).map((f) => f.name), ["app:foo"]);
  assert.deepEqual(m.folderTrail(partial, "b").map((f) => f.name), ["app:foo"]);
});

test("a cycle in the folders cannot hang the breadcrumb", () => {
  const ix = m.indexFolders([folder("a", "a", "b"), folder("b", "b", "a")]);
  assert.ok(m.folderTrail(ix, "a").length <= 2);
});

test("dates: local inputs become instants, and an end before the start is refused", () => {
  assert.equal(m.toInstant(""), undefined);
  assert.equal(m.toInstant("not a date"), undefined);
  assert.match(m.toInstant("2026-10-16T09:30")!, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  assert.equal(m.datesProblem("", ""), null);
  assert.equal(m.datesProblem("2026-10-16T09:30", "2026-10-17T09:30"), null);
  assert.match(m.datesProblem("2026-10-17T09:30", "2026-10-16T09:30")!, /after the start/);
  assert.match(m.datesProblem("2026-10-16T09:30", "2026-10-16T09:30")!, /after the start/);
  assert.equal(m.isFuture("2999-01-01T00:00"), true);
  assert.equal(m.isFuture("2001-01-01T00:00"), false);
});

test("people are found in what was typed or picked", () => {
  assert.equal(m.parseIdentityRef("Alice Chen (#12)"), 12);
  assert.equal(m.parseIdentityRef("#7"), 7);
  assert.equal(m.parseIdentityRef(" 42 "), 42);
  assert.equal(m.parseIdentityRef("Alice"), null);
  assert.equal(m.parseIdentityRef("0"), null);
  assert.equal(m.parseIdentityRef("Bob (#3) extra"), null);
});

// ---------------------------------------------------------------- change preview

const sim = (over: Partial<Parameters<typeof m.summarizeSimulation>[0]> = {}) => ({
  simulated: true, changes: [], added: 1204, removed: 13, truncated: false,
  groups: [
    { group_id: "g2", name: "app:payroll:users", targeted: false, before: 10, after: 12, added: 2, removed: 0, added_sample: [], removed_sample: [] },
    { group_id: "g1", name: "app:payroll:allow", targeted: true, before: 1000, after: 2191, added: 1204, removed: 13, added_sample: [], removed_sample: [] },
    { group_id: "g3", name: "idle", targeted: false, before: 5, after: 5, added: 0, removed: 0, added_sample: [], removed_sample: [] },
  ],
  ...over,
});

test("the change preview says how many identities join and leave, in how many groups", () => {
  const s = m.summarizeSimulation(sim());
  assert.equal(s.headline, "+1,204 / \u221213 identities in 2 groups");
  assert.equal(s.noEffect, false);
  // the groups the change names come first; groups that do not change are left out
  assert.deepEqual(s.groups.map((g) => g.name), ["app:payroll:allow", "app:payroll:users"]);
  assert.equal(s.groups[0].delta, "+1,191");
  assert.equal(s.groups[1].delta, "+2");
});

test("a change with no effect and a truncated one are told apart", () => {
  const none = m.summarizeSimulation(sim({ added: 0, removed: 0, groups: [{ group_id: "g1", name: "x", targeted: true, before: 3, after: 3, added: 0, removed: 0, added_sample: [], removed_sample: [] }] }));
  assert.equal(none.noEffect, true);
  assert.equal(none.headline, "+0 / \u22120 identities in 0 groups");
  const one = m.summarizeSimulation(sim({ truncated: true, added: 1, removed: 0, groups: [{ group_id: "g1", name: "x", targeted: true, before: 3, after: 4, added: 1, removed: 0, added_sample: [], removed_sample: [] }] }));
  assert.match(one.headline, /^at least \+1 \/ \u22120 identities in 1 group$/);
  assert.equal(one.truncated, true);
  assert.equal(m.signed(-5), "\u22125");
  assert.equal(m.signed(0), "0");
});

test("the requests the preview simulates match what is then written", () => {
  assert.deepEqual(m.addChanges("g", [{ identity: 4, reason: "joined" }, { group: "h" }]), [
    { kind: "add_member", group: "g", identity: 4, member_group: undefined, enabled_from: undefined, disabled_at: undefined, reason: "joined" },
    { kind: "add_member", group: "g", identity: undefined, member_group: "h", enabled_from: undefined, disabled_at: undefined, reason: undefined },
  ]);
  assert.deepEqual(m.removeChanges("g", ["4", "h"]), [{ kind: "remove_member", group: "g", member: "4" }, { kind: "remove_member", group: "g", member: "h" }]);
  assert.deepEqual(m.compositeChange("g", "union", ["a", "b"], false), { kind: "set_composite", group: "g", op: "union", factors: ["a", "b"] });
  assert.deepEqual(m.compositeChange("g", "union", ["a", "b"], true, true), { kind: "convert_to_composite", group: "g", op: "union", factors: ["a", "b"], discard_members: true });
});

// ---------------------------------------------------------------- trace

test("a trace path reads from the group down to the row that names the identity", () => {
  const line = m.traceLine([
    { name: "app:payroll:users", via: "start" },
    { name: "app:payroll:allow", via: "factor", op: "complement" },
    { name: "ref:staff", via: "nested" },
  ]);
  assert.equal(line, "app:payroll:users \u203a app:payroll:allow (complement) \u203a ref:staff");
  assert.equal(m.VIA_LABEL.factor, "composite factor");
});

// ---------------------------------------------------------------- history

test("history compare says who joined, who left and how many stayed", () => {
  const p = (id: number, name: string) => ({ identity_id: id, name, start_at: "2026-01-01T00:00:00Z", end_at: null });
  const d = m.diffMembers([p(1, "A"), p(2, "B"), p(3, "C")], [p(2, "B"), p(3, "C"), p(4, "D")]);
  assert.deepEqual(d.added.map((x) => x.name), ["D"]);
  assert.deepEqual(d.removed.map((x) => x.name), ["A"]);
  assert.equal(d.kept, 2);
  const g = m.diffMembers([{ group_id: "x", name: "G", start_at: "", end_at: null }], [{ identity_id: 1, name: "A", start_at: "", end_at: null }]);
  assert.equal(g.added.length, 1);
  assert.equal(g.removed.length, 1);
});

// ---------------------------------------------------------------- composites

test("composite definitions are checked before they are sent", () => {
  assert.equal(m.compositeProblem("complement", ["a", "b"], "g"), null);
  assert.match(m.compositeProblem("complement", ["a", "b", "c"], "g")!, /minus/);
  assert.equal(m.compositeProblem("union", ["a", "b", "c"], "g"), null);
  assert.match(m.compositeProblem("intersection", ["a"], "g")!, /two/);
  assert.match(m.compositeProblem("union", ["a", ""], "g")!, /every factor/);
  assert.match(m.compositeProblem("union", ["a", "g"], "g")!, /itself/);
  assert.match(m.compositeProblem("union", ["a", "a"], "g")!, /once/);
  assert.match(m.compositeProblem("xor", ["a", "b"], "g")!, /combine/);
  assert.equal(m.compositeExpression("complement", ["allow", "deny"]), "allow \u2212 deny");
  assert.equal(m.compositeExpression("union", ["a", "b", "c"]), "a \u222a b \u222a c");
});

// ---------------------------------------------------------------- privileges

test("privileges offered match the object, and inherited ones the kind they apply to", () => {
  assert.ok(m.privilegesFor("group", "self").includes("admin"));
  assert.ok(!m.privilegesFor("group", "self").includes("stem_admin"));
  assert.ok(m.privilegesFor("folder", "self").includes("create"));
  assert.ok(m.privilegesFor("folder", "groups").includes("read"));
  assert.ok(m.privilegesFor("folder", "folders").includes("stem_view"));
  assert.ok(m.privilegesFor("folder", "attr_defs").includes("attr_admin"));
});

test("a grant is built the way the API wants it", () => {
  const f = { privilege: "read", holder: "identity" as const, identity: "12", group: "", appliesTo: "self", scope: "sub" };
  assert.deepEqual(m.grantBody("group", f).body, { privilege: "read", holder_type: "identity", identity: 12 });
  assert.deepEqual(m.grantBody("folder", { ...f, appliesTo: "groups", scope: "one" }).body, { privilege: "read", holder_type: "identity", identity: 12, applies_to: "groups", scope: "one" });
  assert.deepEqual(m.grantBody("group", { ...f, holder: "group", group: "g1" }).body, { privilege: "read", holder_type: "group", group: "g1" });
  assert.deepEqual(m.grantBody("folder", { ...f, holder: "everyone", privilege: "stem_view" }).body, { privilege: "stem_view", holder_type: "everyone" });
  assert.match(m.grantBody("group", { ...f, privilege: "" }).problem!, /privilege/);
  assert.match(m.grantBody("group", { ...f, identity: "" }).problem!, /person/);
  assert.match(m.grantBody("group", { ...f, holder: "group", group: "" }).problem!, /group/);
  assert.match(m.grantBody("group", { ...f, appliesTo: "groups" }).problem!, /folder/);
});

// ---------------------------------------------------------------- attributes

test("attribute values are typed the way the server stores them", () => {
  assert.deepEqual(m.parseAttrValue("integer", " 42 "), { value: 42 });
  assert.ok(m.parseAttrValue("integer", "4.2").problem);
  // a floating value stays a decimal string: never a JSON number
  assert.deepEqual(m.parseAttrValue("floating", "12.50"), { value: "12.50" });
  assert.ok(m.parseAttrValue("floating", "1e3").problem);
  assert.deepEqual(m.parseAttrValue("timestamp", "2026-10-16T00:00:00Z"), { value: "2026-10-16T00:00:00.000Z" });
  assert.ok(m.parseAttrValue("timestamp", "soon").problem);
  assert.deepEqual(m.parseAttrValue("member_id", "9"), { value: 9 });
  assert.ok(m.parseAttrValue("member_id", "0").problem);
  assert.deepEqual(m.parseAttrValue("string", " hi "), { value: "hi" });
  assert.ok(m.parseAttrValue("string", "  ").problem);
});

// ---------------------------------------------------------------- bulk import

test("a members CSV is checked row by row, and a bad row names its line", () => {
  const ok = m.parseMemberRows([
    { identity: "5", enabled_from: "", disabled_at: "", reason: " onboarding " },
    { group: "7c1c0a5e-0000-4000-8000-000000000001" },
  ]);
  assert.deepEqual(ok.problems, []);
  assert.deepEqual(ok.adds[0], { identity: 5, reason: "onboarding" });
  assert.deepEqual(ok.adds[1], { group: "7c1c0a5e-0000-4000-8000-000000000001" });

  const bad = m.parseMemberRows([{ identity: "x" }, { identity: "1", group: "g" }, {}, { identity: "2", enabled_from: "2026-10-17T00:00", disabled_at: "2026-10-16T00:00" }]);
  assert.equal(bad.adds.length, 0);
  assert.equal(bad.problems.length, 4);
  assert.match(bad.problems[0], /^Line 2:/);
  assert.match(bad.problems[3], /^Line 5: .*after the start/);
});

// ---------------------------------------------------------------- new application

test("the application template creates every parent before its children, and every factor before its composite", () => {
  const steps = m.applicationTemplate("payroll");
  const seen = new Set<string>();
  for (const s of steps) {
    const { parent, extension } = m.splitPath(s.path);
    if (parent) assert.ok(seen.has(parent), `${s.path}: its folder ${parent} comes first`);
    assert.equal(m.extensionProblem(extension), null, extension);
    for (const f of s.composite?.factors ?? []) assert.ok(seen.has(f), `${s.path}: factor ${f} comes first`);
    assert.ok(!seen.has(s.path), `${s.path} appears once`);
    seen.add(s.path);
  }
  const policy = steps.find((s) => s.path.endsWith(":payroll_user"))!;
  assert.equal(policy.composite?.op, "complement");
  assert.deepEqual(policy.composite?.factors, ["payroll:service:policy:payroll_user_allow", "payroll:service:policy:payroll_user_deny"]);
  assert.equal(steps[0].path, "payroll");
  assert.equal(m.joinPath("app", "payroll:x"), "app:payroll:x");
  assert.equal(m.joinPath("", "payroll"), "payroll");
});

test("the types the template sets are in the server's vocabulary", () => {
  const folderTypes = ["etc", "org", "test", "service", "app", "security"];
  const groupTypes = ["ref", "basis", "policy", "bundle", "manual", "intermediate"];
  for (const s of m.applicationTemplate("x")) for (const t of s.types ?? []) assert.ok((s.kind === "folder" ? folderTypes : groupTypes).includes(t), `${s.path}: ${t}`);
});

test("idempotency keys fit the server's rule and differ", () => {
  const a = m.idempotencyKey();
  const b = m.idempotencyKey();
  assert.notEqual(a, b);
  assert.match(a, /^[A-Za-z0-9._~:+=-]{1,255}$/);
});

test("planDelete orders groups before folders, deepest folder first, and skips what the UI does not manage", () => {
  const f = (name: string, managed_by = "ui") => ({ kind: "folder" as const, f: { name, managed_by } as any });
  const g = (name: string, managed_by = "ui", status = "active") => ({ kind: "group" as const, g: { name, managed_by, status } as any });
  const p = m.planDelete([f("A"), f("A:B"), g("A:B:G"), g("A:H", "scim"), f("X", "git"), g("A:D", "ui", "deleted"), f("")]);
  assert.deepEqual(p.folders.map((x) => x.name), ["A:B", "A"]);
  assert.deepEqual(p.groups.map((x) => x.name), ["A:B:G"]);
  assert.deepEqual(p.skipped, ["A:H", "X", "A:D", ""]);
  assert.equal(m.deleteTitle({ folders: [1, 2] as any, groups: [1] as any }), "Delete 2 folders and 1 group?");
  assert.equal(m.deleteTitle({ folders: [1] as any, groups: [1, 2] as any }), "Delete 1 folder and 2 groups?");
  assert.equal(m.deleteTitle({ folders: [], groups: [1] as any }), "Delete 1 group?");
  assert.match(m.deleteBody({ folders: [1] as any, groups: [1] as any, skipped: [] }), /empty folder.*restored/);
  assert.equal(m.failureSummary([{ name: "TEST", message: "folder is not empty" }, { name: "G", message: "not found" }]), "TEST: folder is not empty; G: not found");
});

test("planDeleted picks the deleted groups the UI manages and skips the rest", () => {
  const f = (name: string) => ({ kind: "folder" as const, f: { name, managed_by: "ui" } as any });
  const g = (name: string, status: string, managed_by = "ui") => ({ kind: "group" as const, g: { name, status, managed_by } as any });
  const p = m.planDeleted([g("A:G", "deleted"), g("A:H", "active"), g("A:I", "deleted", "loader"), f("A")]);
  assert.deepEqual(p.groups.map((x) => x.name), ["A:G"]);
  assert.deepEqual(p.skipped, ["A:H", "A:I", "A"]);
  assert.equal(m.purgeTitle(1), "Delete 1 group permanently?");
  assert.equal(m.purgeTitle(3), "Delete 3 groups permanently?");
  assert.match(m.purgeBody(2, ["X"]), /cannot be restored.*audit history stays.*another group still uses.*1 item that is not deleted/);
});

test("the tree summary says what goes, in plain words", () => {
  const plan = { folder_id: "f", name: "app", folders: 2, groups: 3, active_groups: 2, deleted_groups: 1, attr_defs: 1, groups_with_members: 2, memberships: 12,
    needs_approval: true, blockers: [], blocker_count: 0 };
  assert.deepEqual(m.treeSummary(plan), ["2 subfolders below it", "3 groups (1 already deleted)", "1 attribute definition", "12 memberships in 2 groups, which stop giving access"]);
  assert.deepEqual(m.treeSummary({ ...plan, folders: 0, groups: 0, deleted_groups: 0, attr_defs: 0, memberships: 0, groups_with_members: 0 }), []);
  assert.deepEqual(m.treeSummary({ ...plan, memberships: 1, groups_with_members: 1, folders: 1, groups: 1, deleted_groups: 0, attr_defs: 0 }),
    ["1 subfolder below it", "1 group", "1 membership in 1 group, which stops giving access"]);
});

test("blockers are listed short, with a count of the rest", () => {
  const b = Array.from({ length: 7 }, (_, i) => ({ reason: `reason ${i}` }));
  assert.deepEqual(m.blockerLines(b, 3), ["reason 0", "reason 1", "reason 2", "and 4 more"]);
  assert.deepEqual(m.blockerLines(b.slice(0, 2)), ["reason 0", "reason 1"]);
});

test("the outcome of a tree delete says whether anything was deleted or a second admin must approve", () => {
  const done = m.treeOutcome("app", { id: "f", deleted: true, recursive: true, folders: 3, groups: 2, attr_defs: 0, memberships: 4 });
  assert.equal(done.requested, false);
  assert.equal(done.message, "Deleted app and everything in it: 3 folders, 2 groups.");
  const pending = m.treeOutcome("app", { status: "pending_approval", change_request_id: "c", type: "t", folder_id: "f", expires_at: null, reason: "2 group(s) in the folder have members", detail: "" });
  assert.equal(pending.requested, true);
  assert.match(pending.message, /^Nothing is deleted yet\. A request to delete app and everything in it was created: a second admin must approve it/);
});

test("a failure names what blocked and why, in plain words", () => {
  assert.equal(m.isNotEmpty("folder_not_empty"), true);
  assert.equal(m.isNotEmpty("not_found"), false);
  assert.equal(m.plainReason("folder_not_empty", "x", { folders: 0, groups: 1, deleted_groups: 1, attr_defs: 0 }),
    "it still holds 1 group (1 deleted); restore or purge the deleted groups, or delete the folder with everything in it");
  assert.equal(m.plainReason("folder_not_empty", "x", { folders: 2, groups: 0, deleted_groups: 0, attr_defs: 1 }),
    "it still holds 2 subfolders, 1 attribute definition; delete the folder with everything in it to remove them too");
  assert.equal(m.plainReason("group_in_use", "x", { groups: ["app:parent"] }), "app:parent still uses it as a member or factor; remove it there first");
  assert.equal(m.plainReason("group_in_use", "x", { groups: ["a", "b"] }), "a, b still use it as a member or factor; remove it there first");
  assert.equal(m.plainReason("recursive_delete_blocked", "x", { blockers: [{ reason: "one" }, { reason: "two" }] }), "one; two");
  assert.equal(m.plainReason("privilege_required", "x", { privilege: "admin" }), "you do not hold the admin privilege on it");
  assert.equal(m.plainReason("not_deleted", "x"), "it is not deleted yet");
  assert.equal(m.plainReason("something_else", "the server said so"), "the server said so");
  assert.equal(m.failureSummary([{ name: "app", message: m.plainReason("group_in_use", "", { groups: ["p"] }) }]), "app: p still uses it as a member or factor; remove it there first");
});

test("a deleted group says who deleted it, when, why and with which folder", () => {
  const when = (iso: string) => `at ${iso.slice(0, 10)}`;
  const g = { status: "deleted", deleted_by: "Alice (tenant admin)", deleted_at: "2026-10-22T14:10:00Z", deleted_reason: "retired", deleted_with_folder: "app" };
  assert.equal(m.deletedLine(g, when), "Deleted by Alice (tenant admin) on at 2026-10-22 — reason: retired — deleted with folder app");
  assert.equal(m.deletedLine({ status: "deleted" }, when), "Deleted");
  assert.equal(m.deletedLine({ ...g, status: "active" }, when), "");
});
