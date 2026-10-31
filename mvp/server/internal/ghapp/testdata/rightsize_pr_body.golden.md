<!-- tessera:lp-rightsize:v1 grant-17 -->
## Tessera right-sizing recommendation

Removes an entitlement nobody is using from a business role. Tessera opened this pull request and never merges it: a person reviews it, and the policy check run on this pull request shows what the change does.

| | |
|---|---|
| Recommendation | `grant-17` (`remove`) |
| Identity | `Esme Thornbury` (`human`) |
| Grant | `workday:emp-1057 → workday:Payroll Administrator` |
| Entitlement removed | `workday:Payroll Administrator` from role `payroll-ops` in `roles/payroll-ops.yaml` |
| Role members who lose it | 1 |
| Permissions lost | 2 (2 unused, 0 used) |
| Usage window | 60 days; never seen in the usage data |
| Confidence | grant evaluated `exact` (never approximate or conditional) |
| Evidence | `GET /api/aws/explanations/ex-9` |

**Unused permissions it removes**

- `payroll:approve_run`
- `payroll:view_salaries`

### Simulation of this change

| Blast radius | Count |
|---|---:|
| Identities gaining access | 0 |
| Identities losing access | 1 |
| Agents gaining access | 0 |
| Agents losing access | 0 |
| Permissions gained / lost (graph) | 0 / 2 |
| AWS paths gained / lost | 0 / 0 |
| Policy violations before / after | 0 / 0 |
| Violations introduced / resolved | 0 / 0 |

<sub>Bundle `abababababab`, preview `cdcdcdcdcdcd`.</sub>
