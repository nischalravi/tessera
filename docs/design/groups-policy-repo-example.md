# Policy groups repository: example layout and CI

Companion to `groups-grouper-parity.md` §8 (GR-9, issue #52). One file defines one group; the file path is
free (the group name is the resource in the policies), but mirroring the name keeps it findable.

```
policy-repo/
  groups/
    app/foo/foo_user.cedar        # group app:foo:service:policy:foo_user
    app/bar/bar_admin.cedar
```

`groups/app/foo/foo_user.cedar`:

```cedar
@display("Foo users")
@owner("app:foo:security:fooAdmin")
@id("allow")
permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:foo:service:policy:foo_user")
when {
  principal in Tessera::Group::"ref:employee:faculty" ||
  (principal in Tessera::Group::"ref:student:enrolled" && principal.type == "person") ||
  principal in Tessera::Group::"app:foo:service:policy:foo_user_allow_manual"
};

@id("deny")
forbid (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:foo:service:policy:foo_user")
when {
  principal in Tessera::Group::"ref:iam:global_deny" ||
  principal in Tessera::Group::"app:foo:service:policy:foo_user_deny_manual"
};
```

Rules in short: members are the union of the permits minus the union of the forbids; an optional attribute
(`department`, `title`, `source`) is read only after `principal has <attr> &&`; context, resource attributes,
arithmetic, dates and extension functions are refused. The manual exception groups
(`..._allow_manual`, `..._deny_manual`) are ordinary groups, edited in the UI or API.

## GitHub Actions snippet (pull request check and merge sync)

This is a snippet for the policy repository, not a workflow of the Tessera repository. `TESSERA_URL` and
`TESSERA_TOKEN` (a machine client with `groups.write`, admin on the policy groups and read on the groups they
use) are repository secrets. Never print the token.

```yaml
name: policy-groups
on:
  pull_request: { paths: ["groups/**"] }
  push: { branches: [main], paths: ["groups/**"] }
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate offline
        run: tessera groups policy validate -dir .
      - name: Diff against the tenant
        if: github.event_name == 'pull_request'
        env: { TESSERA_URL: "${{ secrets.TESSERA_URL }}", TESSERA_TOKEN: "${{ secrets.TESSERA_TOKEN }}" }
        run: |
          # body.json: {"full":true,"files":[{"path":"groups/...cedar","cedar":"<file text>"}, ...]}
          # (for example, built with jq --rawfile over each *.cedar file)
          curl -sS -H "Authorization: Bearer $TESSERA_TOKEN" -H 'Content-Type: application/json' \
            --data @body.json "$TESSERA_URL/api/groups/policy/diff" > diff.json
          # post diff.json (per group: added, removed, samples) as the pull request comment
  apply:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Apply the commit
        env: { TESSERA_URL: "${{ secrets.TESSERA_URL }}", TESSERA_TOKEN: "${{ secrets.TESSERA_TOKEN }}" }
        run: |
          # body: {"origin":"repo","commit":"$GITHUB_SHA","full":true,"files":[{"path":..., "cedar":...}]}
          curl -sS -H "Authorization: Bearer $TESSERA_TOKEN" -H 'Content-Type: application/json' \
            --data @body.json "$TESSERA_URL/api/groups/policy/apply"
```

Apply is atomic: a finding in any file (`422 invalid_policy`) changes nothing. `full: true` makes the files
the whole repository: a group whose file is gone is retired (it becomes an empty set and can be brought back
by restoring its file). The commit is recorded on each changed group (`policy_ref`), on every event the
sync causes (`cause_type policy_repo`, `cause_ref` the commit) and in the `groups.policy.applied` audit event.
