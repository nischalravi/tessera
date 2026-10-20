package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// designRoutes is the route -> requirement table of the designs, transcribed:
// docs/design/phase-0-platform-security.md §16.2 (existing routes) and §16.1
// (session and audit routes), and docs/design/deployment-readiness.md §9
// (readiness routes) and issue #163 (conditional access), and the secret-rotation routes of issue #113 (docs in
// internal/api/openapi_rotation.json). Columns: method, pattern, permission, step-up
// (STEP_UP_POLICY or -). "public" marks the allow-list. Routes that neither
// design names (GET /api/accounts, the API description) are marked with a
// trailing "#" and the requirement chosen for them in this PR.
const designRoutes = `
GET    /api/health                                   public
GET    /api/connectors                               graph.read      -
POST   /api/connectors/sync                          connectors.sync -
GET    /api/summary                                  graph.read      -
GET    /api/identities                               graph.read      -
GET    /api/identities/{identity_id}                 graph.read      -
GET    /api/accounts                                 graph.read      -  #
GET    /api/groups                                   graph.read      -
GET    /api/resources                                graph.read      -
GET    /api/graph                                    graph.read      -
GET    /api/nhi                                      graph.read      -
GET    /api/ai-agents                                graph.read      -  # issue #116
GET    /api/ai-agents/mcp-findings                   graph.read      -  # issue #116
GET    /api/least-privilege/recommendations          graph.read      -
POST   /api/least-privilege/revoke                   graph.read      -  (dry_run=false: grants.revoke + STEP_UP_POLICY in the handler)
GET    /api/policies                                 graph.read      -
GET    /api/violations                               graph.read      -
POST   /api/simulate                                 graph.read      -
GET    /api/jit/requests                             graph.read      -
POST   /api/jit/requests                             jit.request     -
POST   /api/jit/requests/{request_id}/approve        jit.decide      STEP_UP_POLICY
POST   /api/jit/requests/{request_id}/deny           jit.deny_revoke -
POST   /api/jit/requests/{request_id}/revoke         jit.deny_revoke -
POST   /api/jit/sweep                                jit.sweep       -
GET    /api/reviews/campaigns                        graph.read      -
POST   /api/reviews/campaigns                        reviews.manage  -
GET    /api/reviews/campaigns/{campaign_id}          graph.read      -
POST   /api/reviews/items/{item_id}/decision         reviews.decide  STEP_UP_POLICY
GET    /api/reviews/campaigns/{campaign_id}/population  graph.read   -  # issue #110
GET    /api/reviews/campaigns/{campaign_id}/export   reviews.export  -  # issue #110
POST   /api/reviews/qa/{qa_id}/decision              reviews.decide  STEP_UP_POLICY  # issue #110
PUT    /api/reviews/settings                         reviews.manage  -  # issue #110
GET    /api/reviews/schedules                        graph.read      -  # issue #166
POST   /api/reviews/schedules                        reviews.manage  -  # issue #166
PUT    /api/reviews/schedules/{schedule_id}          reviews.manage  -  # issue #166
POST   /api/reviews/schedules/{schedule_id}/run      reviews.manage  -  # issue #166
GET    /api/hris/events                              graph.read      -
POST   /api/hris/events                              hris.simulate_event -
GET    /api/hris/events/{event_id}/plan              graph.read      -
POST   /api/hris/events/{event_id}/execute           hris.execute    STEP_UP_POLICY
GET    /api/jml/leaver-plan/{identity_id}            graph.read      -
GET    /api/siem/sinks                               siem.read       -  # issue #169
POST   /api/siem/sinks                               siem.configure  STEP_UP_POLICY  # issue #169
PUT    /api/siem/sinks/{sink_id}                     siem.configure  STEP_UP_POLICY  # issue #169
POST   /api/siem/sinks/{sink_id}/rewind              siem.configure  -  # issue #169
POST   /api/siem/sinks/{sink_id}/test                siem.configure  -  # issue #169
GET    /api/siem/sinks/{sink_id}/dead-letters        siem.read       -  # issue #169
GET    /api/alerts                                   alerts.read     -  # issue #168
GET    /api/alerts/summary                           alerts.read     -  # issue #168
GET    /api/alerts/rules                             alerts.read     -  # issue #168
PUT    /api/alerts/rules/{rule_id}                   alerts.configure -  # issue #168
GET    /api/alerts/channels                          alerts.configure -  # issue #168
POST   /api/alerts/channels                          alerts.configure STEP_UP_POLICY  # issue #168
PUT    /api/alerts/channels/{channel_id}             alerts.configure STEP_UP_POLICY  # issue #168
POST   /api/alerts/channels/{channel_id}/test        alerts.configure -  # issue #168
GET    /api/alerts/{alert_id}                        alerts.read     -  # issue #168
POST   /api/alerts/{alert_id}/acknowledge            alerts.manage   -  # issue #168
POST   /api/alerts/{alert_id}/resolve                alerts.manage   -  # issue #168
POST   /api/alerts/{alert_id}/assign                 alerts.manage   -  # issue #168
GET    /api/ownership                                graph.read      -  # issue #167
PUT    /api/ownership/{kind}/{object_key}            ownership.manage -  # issue #167
POST   /api/ownership/bulk                           ownership.manage -  # issue #167
GET    /openapi.json                                 auth.self       -  #
GET    /docs                                         auth.self       -  #
GET    /docs/oauth2-redirect                         auth.self       -  #
GET    /redoc                                        auth.self       -  #
GET    /api/audit                                    audit.read      -
GET    /api/audit/events/{event_id}/proof            audit.read      -
GET    /api/audit/checkpoints                        audit.read      -
GET    /api/audit/keys                               audit.read      -
POST   /api/audit/verify                             audit.verify    -
GET    /api/audit/export                             audit.read      -
GET    /api/readiness/templates                      connections.read   -
GET    /api/readiness/templates/{type}               connections.read   -
PUT    /api/readiness/overlays/{type}                connections.manage STEP_UP_POLICY
GET    /api/readiness/openapi.json                   auth.self          -  #
GET    /api/connections                              connections.read   -
POST   /api/connections                              connections.manage -
GET    /api/connections/{id}                         connections.read   -
PATCH  /api/connections/{id}/config                  connections.manage STEP_UP_POLICY
PUT    /api/connections/{id}/credential              connections.manage STEP_UP_POLICY
GET    /api/connections/{id}/checklist               connections.read   -
POST   /api/connections/{id}/checklist/{item}/attest connections.manage -
POST   /api/connections/{id}/checklist/{item}/attest-instead connections.manage STEP_UP_POLICY  # issue #217
POST   /api/connections/{id}/checklist/{item}/skip   connections.manage -
DELETE /api/connections/{id}/checklist/{item}/skip   connections.manage -
POST   /api/connections/{id}/transition              connections.manage -
POST   /api/connections/{id}/activate                connections.activate STEP_UP_POLICY
POST   /api/connections/{id}/retire                  connections.manage STEP_UP_POLICY
GET    /api/aws/connectors                           connections.read   -  # issue #26
POST   /api/aws/connectors                           connections.manage STEP_UP_POLICY  # issue #26
DELETE /api/aws/connectors/{id}                      connections.manage STEP_UP_POLICY  # issue #26
GET    /api/aws/snapshots                            connections.read   -  # issue #26
GET    /api/aws/snapshots/{id}                       connections.read   -  # issue #26
GET    /api/aws/can                                  graph.read         -  # issue #30
GET    /api/aws/principals/{arn}/effective           graph.read         -  # issue #30
GET    /api/aws/resources/{arn}/who-can              graph.read         -  # issue #30
GET    /api/aws/explanations/{id}                    graph.read         -  # issue #30
POST   /api/aws/simulate-policy-change               graph.read         -  # issue #30 (a comment post: connections.manage + STEP_UP_POLICY in the handler)
GET    /api/aws/pr-comment                           connections.read   -  # issue #30
PUT    /api/aws/pr-comment                           connections.manage STEP_UP_POLICY  # issue #30
GET    /api/correlation/queue                        graph.read      -  # issue #160
GET    /api/correlation/decisions                    graph.read      -  # issue #160
POST   /api/accounts/{account_id}/link               identities.correlate STEP_UP_POLICY  # issue #160
POST   /api/accounts/{account_id}/not-person         identities.correlate STEP_UP_POLICY  # issue #160
DELETE /api/accounts/{account_id}/link               identities.correlate STEP_UP_POLICY  # issue #160
POST   /api/identities/{identity_id}/merge           identities.merge STEP_UP_POLICY  # issue #160
GET    /api/identity-merges                          graph.read      -  # issue #160
GET    /api/identities/{identity_id}/affiliations    graph.read      -  # issue #64
GET    /api/affiliation-summary                      graph.read      -  # issue #76
GET    /api/identities/{identity_id}/guest-profile   guests.read     -  # issue #76
GET    /api/identities/{identity_id}/identifiers     graph.read      -  # issue #64
POST   /api/identities/{identity_id}/affiliations    identities.affiliate STEP_UP_POLICY  # issue #64
POST   /api/affiliations/{affiliation_id}/end        identities.affiliate STEP_UP_POLICY  # issue #64
GET    /api/identities/{identity_id}/access-bundle   guests.read     -  # issue #75
GET    /api/refgroups                                graph.read      -  # issue #75
POST   /api/refgroups/reconcile                      lifecycle.manage -  # issue #75
POST   /api/identity-merges/{merge_id}/unmerge       identities.merge STEP_UP_POLICY  # issue #160
GET    /api/identity-matches                         identity_matches.review -  # issue #68
POST   /api/identity-matches/{match_id}/decide       identity_matches.review STEP_UP_POLICY  # issue #68
GET    /api/identity-merge-requests                  identities.merge -  # issue #68
POST   /api/identity-merge-requests/{merge_request_id}/approve identities.merge STEP_UP_POLICY  # issue #68
POST   /api/identity-merge-requests/{merge_request_id}/reject  identities.merge STEP_UP_POLICY  # issue #68
GET    /api/admin/matching                           matching.configure -  # issue #68
PUT    /api/admin/matching                           matching.configure STEP_UP_POLICY  # issue #68
GET    /api/guest-lifecycle                          guests.read     -  # issue #74
GET    /api/guest-lifecycle/items                    guests.read     -  # issue #74
GET    /api/guest-lifecycle/tasks                    guests.sponsor  -  # issue #74 (only the tasks the caller may decide)
POST   /api/guest-lifecycle/tasks/{task_id}/resolve  guests.sponsor  STEP_UP_POLICY  # issue #74 (the manager of the departed sponsor, sponsorships.approve or the sponsor, in the service)
GET    /api/admin/guest-lifecycle                    guest_lifecycle.configure -  # issue #74
PUT    /api/admin/guest-lifecycle                    guest_lifecycle.configure STEP_UP_POLICY  # issue #74
GET    /api/admin/terms                              guests.read     -  # issue #73
POST   /api/admin/terms                              terms.manage    STEP_UP_POLICY  # issue #73
PUT    /api/admin/terms/{key}/assignments            terms.manage    STEP_UP_POLICY  # issue #73
GET    /api/me/terms                                 auth.self        -  # issue #73 (the caller's own person)
POST   /api/me/terms/accept                          auth.self        -  # issue #73 (the caller's own person)
POST   /api/me/recovery-codes                        auth.self        -  # issue #73 (hosted identities only)
POST   /api/guests/{identity_id}/recovery            guests.sponsor  STEP_UP_POLICY  # issue #73 (the guest's sponsor, or guests.recover, in the handler)
GET    /api/guest-recoveries                         guests.read     -  # issue #73
POST   /api/guest-recoveries/{case_id}/cancel        guests.sponsor  STEP_UP_POLICY  # issue #73 (the guest's sponsor, or guests.recover, in the handler)
GET    /api/catalog                                  requests.create -  # issue #164 (?all=1: catalog.manage in the handler)
PUT    /api/catalog/items/{group_id}                 catalog.manage  STEP_UP_POLICY  # issue #164
POST   /api/requests                                 requests.create -  # issue #164 (others: requests.create_for_others in the handler)
GET    /api/requests                                 requests.create -  # issue #164 (scope=pending|all: requests.decide or graph.read)
GET    /api/requests/{request_id}                    requests.create -  # issue #164
POST   /api/requests/{request_id}/approve            requests.create STEP_UP_POLICY  # issue #164 (#165: the line's routing decides who)
POST   /api/requests/{request_id}/deny               requests.create -  # issue #164 (#165: the line's routing decides who)
POST   /api/requests/{request_id}/cancel             requests.create -  # issue #164 (the requester)
POST   /api/requests/{request_id}/remove             requests.create -  # issue #164 (requests.decide, or the beneficiary)
GET    /api/roles                                    requests.create -  # issue #161
POST   /api/roles                                    roles.manage    STEP_UP_POLICY  # issue #161
GET    /api/roles/{role_id}                          graph.read      -  # issue #161
PUT    /api/roles/{role_id}                          roles.manage    STEP_UP_POLICY  # issue #161
GET    /api/roles/{role_id}/versions                 graph.read      -  # issue #161
GET    /api/roles/{role_id}/drift                    graph.read      -  # issue #161
POST   /api/roles/{role_id}/retire                   roles.manage    STEP_UP_POLICY  # issue #161
POST   /api/roles/{role_id}/reconcile                roles.manage    STEP_UP_POLICY  # issue #161
POST   /api/roles/{role_id}/members                  roles.manage    STEP_UP_POLICY  # issue #161
POST   /api/roles/{role_id}/members/{identity_id}/remove roles.manage STEP_UP_POLICY  # issue #161
GET    /api/roles/{role_id}/exclusions               graph.read      -  # issue #214
POST   /api/roles/{role_id}/exclusions/{identity_id}/remove roles.manage STEP_UP_POLICY  # issue #214
GET    /api/roles/{role_id}/flags                    graph.read      -  # issue #214
GET    /api/abac/policies                            graph.read      -  # issue #162
POST   /api/abac/policies                            roles.manage    STEP_UP_POLICY  # issue #162
GET    /api/abac/policies/{policy_id}                graph.read      -  # issue #162
PUT    /api/abac/policies/{policy_id}                roles.manage    STEP_UP_POLICY  # issue #162
POST   /api/abac/policies/{policy_id}/retire         roles.manage    STEP_UP_POLICY  # issue #162
POST   /api/abac/simulate                            graph.read      -  # issue #162
GET    /api/abac/bindings                            graph.read      -  # issue #162
PUT    /api/catalog/items/{group_id}/policy          catalog.manage  STEP_UP_POLICY  # issue #162
POST   /api/removal-requests                         requests.create -  # wire-previews (others: requests.create_for_others in the handler)
GET    /api/removal-requests                         requests.create -  # wire-previews (scope=pending|all: requests.decide or graph.read; approvals: what you may decide)
POST   /api/removal-requests/{request_id}/approve    requests.create STEP_UP_POLICY  # wire-previews (the manager, a delegate or requests.decide: the handler checks)
POST   /api/removal-requests/{request_id}/deny       requests.create -  # wire-previews
POST   /api/removal-requests/{request_id}/cancel     requests.create -  # wire-previews (the requester)
GET    /api/activity                                 auth.self       -  # wire-previews (the caller's own ledger events)
GET    /api/orgs                                     graph.read      -  # wire-previews (derived from departments)
GET    /api/orgs/{org_id}                            graph.read      -  # wire-previews
GET    /api/request-drafts                           requests.create -  # wire-previews (the caller's own drafts)
POST   /api/request-drafts                           requests.create -  # wire-previews
GET    /api/request-drafts/{draft_id}                requests.create -  # wire-previews (the caller's own)
PUT    /api/request-drafts/{draft_id}                requests.create -  # wire-previews (the caller's own)
DELETE /api/request-drafts/{draft_id}                requests.create -  # wire-previews (the caller's own)
POST   /api/role-requests                            requests.create -  # issue #161 (others: requests.create_for_others in the handler)
GET    /api/role-requests                            requests.create -  # issue #161 (scope=pending|all: requests.decide or graph.read)
POST   /api/role-requests/{request_id}/approve       requests.decide STEP_UP_POLICY  # issue #161
POST   /api/role-requests/{request_id}/deny          requests.decide -  # issue #161
POST   /api/role-requests/{request_id}/cancel        requests.create -  # issue #161 (the requester)
GET    /api/lifecycle                                graph.read      -  # issue #159
GET    /api/lifecycle/sponsored                      requests.create -  # issue #159
POST   /api/lifecycle/sweep                          lifecycle.manage -  # issue #159
GET    /api/identities/{identity_id}/lifecycle       graph.read      -  # issue #159
PUT    /api/identities/{identity_id}/lifecycle       lifecycle.manage STEP_UP_POLICY  # issue #159
POST   /api/identities/{identity_id}/lifecycle/extend requests.create -  # issue #159 (the sponsor, or lifecycle.manage)
POST   /api/guests/invitations                       guests.sponsor  STEP_UP_POLICY  # issue #65 (the sponsor policy decides who may sponsor)
POST   /api/guests/invitations/bulk                  guests.sponsor  STEP_UP_POLICY  # issue #65 (dry_run too: it audits)
GET    /api/guest-registrations                      guests.sponsor  -  # issue #66 (only the caller's own pending requests)
POST   /api/guest-registrations/code                 guests.sponsor  STEP_UP_POLICY  # issue #66
POST   /api/guest-registrations/{registration_id}/approve  guests.sponsor  STEP_UP_POLICY  # issue #66 (only the sponsor the request names; the sponsor policy still decides)
POST   /api/guest-registrations/{registration_id}/deny     guests.sponsor  STEP_UP_POLICY  # issue #66 (only the sponsor the request names)
GET    /api/guests                                   guests.sponsor  -  # issue #65 (sponsor=all: guests.read in the handler)
GET    /api/sponsorships/approvals                   sponsorships.approve -  # issue #65
GET    /api/sponsorships/{sponsorship_id}            guests.sponsor  -  # issue #65 (the sponsor, the transfer target, guests.read or sponsorships.approve)
POST   /api/sponsorships/{sponsorship_id}/approve    sponsorships.approve STEP_UP_POLICY  # issue #65
POST   /api/sponsorships/{sponsorship_id}/reject     sponsorships.approve STEP_UP_POLICY  # issue #65
POST   /api/sponsorships/{sponsorship_id}/renew      guests.sponsor  STEP_UP_POLICY  # issue #65 (the sponsor)
POST   /api/sponsorships/{sponsorship_id}/end        guests.sponsor  STEP_UP_POLICY  # issue #65 (the sponsor, or sponsorships.approve)
POST   /api/sponsorships/{sponsorship_id}/transfer   guests.sponsor  STEP_UP_POLICY  # issue #65 (the sponsor)
POST   /api/sponsorships/{sponsorship_id}/accept-transfer guests.sponsor STEP_UP_POLICY  # issue #65 (the person asked)
POST   /api/guests/{identity_id}/resend-invitation   guests.sponsor  STEP_UP_POLICY  # issue #69 (the sponsor, or sponsorships.approve; checked in the handler)
POST   /api/guests/{identity_id}/revoke-invitation   guests.sponsor  STEP_UP_POLICY  # issue #69 (the sponsor, or sponsorships.approve; checked in the handler)
GET    /api/approvals/inbox                          requests.create -  # issue #165
GET    /api/approvals/delegates                      requests.create -  # issue #165
GET    /api/approvals/delegations                    requests.create -  # issue #165 (?all=1: requests.decide)
POST   /api/approvals/delegations                    requests.create -  # issue #165
POST   /api/approvals/delegations/{delegation_id}/revoke requests.create -  # issue #165
GET    /api/notifications                            auth.self       -  # issue #189 (the caller's own inbox)
POST   /api/notifications/read                       auth.self       -  # issue #189
GET    /api/notifications/preferences                auth.self       -  # issue #189
PUT    /api/notifications/preferences                auth.self       -  # issue #189
GET    /api/email/messages                           email.read      -  # issue #189
GET    /api/email/messages/{message_id}              email.read      -  # issue #189
POST   /api/email/messages/{message_id}/retry        email.manage    -  # issue #189
POST   /api/identities/{identity_id}/contain         identities.contain STEP_UP_POLICY  # issue #106
GET    /api/identities/{identity_id}/containment     graph.read      -  # issue #106
POST   /api/identities/{identity_id}/disable         identities.contain STEP_UP_POLICY  # wire-previews: containment, then disabled
POST   /api/identities/{identity_id}/enable          identities.contain STEP_UP_POLICY  # wire-previews: restores what Disable disabled
GET    /api/identities/{identity_id}/disables        graph.read      -  # wire-previews
POST   /api/containment-retries/{retry_id}/retry-now identities.contain STEP_UP_POLICY  # issue #106
PUT    /api/connections/{id}/containment-credential  connections.manage STEP_UP_POLICY  # issue #106
GET    /t/{slug}/mcp/.well-known/oauth-authorization-server public  # issue #115
GET    /t/{slug}/mcp/.well-known/oauth-protected-resource/{resource_id} public  # issue #115
GET    /t/{slug}/mcp/.well-known/jwks.json           public  # issue #115
POST   /t/{slug}/mcp/oauth/token                     public  # issue #115
POST   /t/{slug}/mcp/oauth/introspect                public  # issue #115
POST   /t/{slug}/mcp/oauth/revoke                    public  # issue #115
POST   /t/{slug}/mcp/oauth/decisions                 public  # issue #115
GET    /t/{slug}/mcp/oauth/authorize                 auth.self       -  # issue #115
GET    /api/mcp/authorizations/{id}                  auth.self       -  # issue #115
POST   /api/mcp/authorizations/{id}/decision         auth.self       STEP_UP_POLICY  # issue #115
GET    /api/mcp/clients                              graph.read      -  # issue #115
POST   /api/mcp/clients                              agents.manage   STEP_UP_POLICY  # issue #115
PUT    /api/mcp/clients/{id}                         agents.manage   STEP_UP_POLICY  # issue #115
GET    /api/mcp/resources                            graph.read      -  # issue #115
POST   /api/mcp/resources                            agents.manage   STEP_UP_POLICY  # issue #115
PUT    /api/mcp/resources/{id}                       agents.manage   STEP_UP_POLICY  # issue #115
GET    /api/mcp/tokens                               graph.read      -  # issue #115
POST   /api/mcp/tokens/{jti}/revoke                  agents.manage   STEP_UP_POLICY  # issue #115
GET    /api/mcp/decisions                            graph.read      -  # issue #115
GET    /api/ssf/transmitters                         graph.read      -  # issue #114
GET    /api/ssf/transmitters/{id}                    graph.read      -  # issue #114
GET    /api/ssf/events                               graph.read      -  # issue #114
POST   /api/ssf/transmitters                         ssf.configure   STEP_UP_POLICY  # issue #114
PUT    /api/ssf/transmitters/{id}                    ssf.configure   STEP_UP_POLICY  # issue #114
DELETE /api/ssf/transmitters/{id}                    ssf.configure   STEP_UP_POLICY  # issue #114
POST   /api/ssf/transmitters/{id}/verify             ssf.configure   STEP_UP_POLICY  # issue #114
POST   /public/t/{slug}/ssf/{transmitter_id}/events  public          # issue #114: bearer secret, RFC 8935
GET    /api/agents                                   connections.read   -  # issue #92
POST   /api/agents                                   connections.manage STEP_UP_POLICY  # issue #92
POST   /api/agents/{id}/revoke                       connections.manage STEP_UP_POLICY  # issue #92
GET    /api/flatfile/apps                            graph.read      -  # issue #105
PUT    /api/flatfile/apps/{system}/mapping           flatfile.manage STEP_UP_POLICY  # issue #105
POST   /api/flatfile/apps/{system}/uploads           flatfile.upload -  # issue #105
GET    /api/flatfile/uploads                         graph.read      -  # issue #105
GET    /api/flatfile/uploads/{upload_id}             graph.read      -  # issue #105
GET    /api/flatfile/tasks                           graph.read      -  # issue #105
POST   /api/flatfile/tasks/{task_id}/close           flatfile.close_tasks STEP_UP_POLICY  # issue #105
GET    /api/access/as-of                             graph.read      -  # issue #111
GET    /api/evidence/packs                           audit.read      -  # issue #111
POST   /api/evidence/packs                           audit.read      -  # issue #111
GET    /api/evidence/packs/{pack_id}                 audit.read      -  # issue #111
GET    /api/evidence/packs/{pack_id}/download        audit.read      -  # issue #111
GET    /api/helpdesk/cases                           graph.read      -  # issue #108
POST   /api/helpdesk/cases                           helpdesk.reset  -  # issue #108
GET    /api/helpdesk/cases/{case_id}                 graph.read      -  # issue #108
POST   /api/helpdesk/cases/{case_id}/verifications   helpdesk.reset  -  # issue #108
POST   /api/helpdesk/cases/{case_id}/manager-approval helpdesk.approve STEP_UP_POLICY  # issue #108
POST   /api/helpdesk/cases/{case_id}/second-approval helpdesk.approve STEP_UP_POLICY  # issue #108
POST   /api/helpdesk/cases/{case_id}/execute         helpdesk.reset  STEP_UP_POLICY  # issue #108
POST   /api/helpdesk/cases/{case_id}/cancel          helpdesk.reset  -  # issue #108
GET    /api/helpdesk/findings                        graph.read      -  # issue #108
POST   /api/helpdesk/signals                         helpdesk.approve -  # issue #108
POST   /api/connections/{id}/validate                connections.manage -
GET    /api/connections/{id}/validations/{run}       connections.read   -
POST   /api/connections/{id}/dry-run                 connections.manage -
GET    /api/connections/{id}/dry-runs/{run}          connections.read   -
GET    /api/connections/{id}/findings                connections.read   -
POST   /api/connections/{id}/findings/{fid}/accept   connections.manage -  (critical finding: STEP_UP_POLICY in the handler)
GET    /api/connections/{id}/health                  connections.read   -
GET    /api/connections/{id}/activation              connections.read   -  # DR-10
POST   /api/connections/{id}/activation/approve      connections.activate STEP_UP_POLICY  # DR-10
POST   /api/connections/{id}/activation/reject       connections.activate -  # DR-10
GET    /api/insights/deployment-health               connections.read   -
POST   /api/insights/deployment-health/rerun         connections.manage -
GET    /api/connections/{id}/readiness/evidence      connections.read   -  (+ audit.read in the handler; the design's audit.export does not exist)
GET    /api/insights/deployment-health/evidence      connections.read   -  (+ audit.read in the handler; the design's audit.export does not exist)
GET    /api/access/policies                          conditional_access.read   -
POST   /api/access/policies                          conditional_access.manage STEP_UP_POLICY
PUT    /api/access/policies/{id}                     conditional_access.manage STEP_UP_POLICY
DELETE /api/access/policies/{id}                     conditional_access.manage STEP_UP_POLICY
GET    /api/access/networks                          conditional_access.read   -
POST   /api/access/networks                          conditional_access.manage STEP_UP_POLICY
PUT    /api/access/networks/{id}                     conditional_access.manage STEP_UP_POLICY
DELETE /api/access/networks/{id}                     conditional_access.manage STEP_UP_POLICY
GET    /api/access/users                             conditional_access.read   -
GET    /api/access/device-signals                    conditional_access.read   -
PUT    /api/access/device-signals/{user_id}          conditional_access.manage STEP_UP_POLICY
DELETE /api/access/device-signals/{user_id}          conditional_access.manage STEP_UP_POLICY
POST   /api/access/evaluate                          conditional_access.read   -
GET    /api/sod/functions                            graph.read      -  # issue #298
POST   /api/sod/functions                            sod.manage      STEP_UP_POLICY  # issue #298
GET    /api/sod/functions/{function_id}              graph.read      -  # issue #298
PUT    /api/sod/functions/{function_id}              sod.manage      STEP_UP_POLICY  # issue #298
POST   /api/sod/functions/{function_id}/retire       sod.manage      STEP_UP_POLICY  # issue #298
GET    /api/sod/risks                                graph.read      -  # issue #298
POST   /api/sod/risks                                sod.manage      STEP_UP_POLICY  # issue #298
GET    /api/sod/risks/{risk_id}                      graph.read      -  # issue #298
PUT    /api/sod/risks/{risk_id}                      sod.manage      STEP_UP_POLICY  # issue #298
POST   /api/sod/risks/{risk_id}/retire               sod.manage      STEP_UP_POLICY  # issue #298
GET    /api/sod/rulesets                             graph.read      -  # issue #298
POST   /api/sod/rulesets                             sod.manage      STEP_UP_POLICY  # issue #298
POST   /api/sod/rulesets/import                      sod.manage      STEP_UP_POLICY  # issue #298
GET    /api/sod/rulesets/{ruleset_id}                graph.read      -  # issue #298
PUT    /api/sod/rulesets/{ruleset_id}                sod.manage      STEP_UP_POLICY  # issue #298
POST   /api/sod/rulesets/{ruleset_id}/retire         sod.manage      STEP_UP_POLICY  # issue #298
GET    /api/sod/rulesets/{ruleset_id}/export         graph.read      -  # issue #298
POST   /api/sod/import-legacy                        sod.manage      STEP_UP_POLICY  # issue #298
GET    /api/sod/violations                           graph.read      -  # issue #298
GET    /api/sod/controls                             graph.read      -  # issue #298
POST   /api/sod/controls                             sod.manage      STEP_UP_POLICY  # issue #298
GET    /api/sod/controls/{control_id}                graph.read      -  # issue #298
PUT    /api/sod/controls/{control_id}                sod.manage      STEP_UP_POLICY  # issue #298
POST   /api/sod/controls/{control_id}/retire         sod.manage      STEP_UP_POLICY  # issue #298
GET    /api/sod/mitigations                          graph.read      -  # issue #298
POST   /api/sod/mitigations                          sod.mitigate    -  # issue #298
POST   /api/sod/mitigations/{mitigation_id}/approve  sod.approve     STEP_UP_POLICY  # issue #298 (not the requester)
POST   /api/sod/mitigations/{mitigation_id}/reject   sod.approve     -  # issue #298 (not the requester)
POST   /api/sod/mitigations/{mitigation_id}/cancel   sod.mitigate    -  # issue #298 (the requester)
POST   /api/sod/mitigations/{mitigation_id}/revoke   requests.create -  # issue #298 (risk owner or sod.approve; step-up in the handler)
POST   /api/sod/violations/escalate                  sod.mitigate    -  # issue #298
POST   /api/sod/violations/revoke                    graph.read      -  # issue #298 (applying: grants.revoke and step-up in the handler)
GET    /api/sod/review-context                       graph.read      -  # issue #298
POST   /api/sod/simulate                             requests.create -  # issue #298
GET    /api/jobs                                     jobs.read       -  # issue #172
GET    /api/jobs/{job_id}                            jobs.read       -  #
POST   /api/jobs/{job_id}/retry                      jobs.read       -  # (the replayed route's own permission and step-up apply)
GET    /api/queue/jobs                               jobs.read       -  # issue #300
GET    /api/queue/schedules                          jobs.read       -  #
POST   /api/queue/jobs/{job_id}/retry                jobs.manage     STEP_UP_POLICY  #
GET    /api/provisioning/targets                     provisioning.read   -  # issue #103
PUT    /api/provisioning/targets/{id}                connections.manage  STEP_UP_POLICY
DELETE /api/provisioning/targets/{id}                connections.manage  STEP_UP_POLICY
GET    /api/provisioning/ops                         provisioning.read   -
GET    /api/provisioning/ops/{op_id}                 provisioning.read   -
POST   /api/provisioning/ops/{op_id}/retry           provisioning.manage -
POST   /api/provisioning/ops/{op_id}/cancel          provisioning.manage -
POST   /api/provisioning/run                         provisioning.manage -
GET    /api/provisioning/findings                    provisioning.read   -
GET    /api/access-drift                             drift.read      -  # issue #301
POST   /api/access-drift/run                         drift.remediate -
POST   /api/access-drift/{drift_id}/accept           drift.remediate STEP_UP_POLICY
POST   /api/access-drift/{drift_id}/remediate        drift.remediate STEP_UP_POLICY
GET    /api/remediation-policies                     drift.read      -
PUT    /api/remediation-policies                     drift.policy    STEP_UP_POLICY
DELETE /api/remediation-policies/{policy_id}         drift.policy    STEP_UP_POLICY
GET    /api/rotation/openapi.json                    auth.self          -  #
GET    /api/rotation/overview                        graph.read         -
GET    /api/rotation/adapters                        graph.read         -
PUT    /api/rotation/adapters/{name}                 secrets.rotate     STEP_UP_POLICY
DELETE /api/rotation/adapters/{name}                 secrets.rotate     STEP_UP_POLICY
GET    /api/rotation/policies                        graph.read         -
PUT    /api/rotation/policies                        secrets.rotate     STEP_UP_POLICY
DELETE /api/rotation/policies/{id}                   secrets.rotate     STEP_UP_POLICY
POST   /api/rotation/plan                            graph.read         -  (a dry run: computed data, no provider call)
GET    /api/rotation/jobs                            graph.read         -
POST   /api/rotation/jobs                            secrets.rotate     STEP_UP_POLICY
GET    /api/rotation/jobs/{id}                       graph.read         -
POST   /api/rotation/jobs/{id}/retry                 secrets.rotate     STEP_UP_POLICY
POST   /api/rotation/jobs/{id}/cancel                secrets.rotate     STEP_UP_POLICY
POST   /api/rotation/bulk/plan                       graph.read         -  (a dry run)
GET    /api/rotation/bulk                            graph.read         -
POST   /api/rotation/bulk                            secrets.rotate     STEP_UP_POLICY
GET    /api/rotation/bulk/{id}                       graph.read         -
GET    /api/config/signing-key                       admin.read      -  # issue #170
POST   /api/config/export                            config.transport -  #
GET    /api/config/trusted-signers                   admin.read      -  #
POST   /api/config/trusted-signers                   config.transport STEP_UP_POLICY #
DELETE /api/config/trusted-signers/{kid}             config.transport STEP_UP_POLICY #
POST   /api/config/import/plan                       config.transport -  #
POST   /api/config/import/apply                      config.transport STEP_UP_POLICY #
GET    /api/config/imports                           admin.read      -  #
GET    /api/auth/oauth2/{connection_id}/callback     public
GET    /t/{slug}/.well-known/oauth-authorization-server public
GET    /t/{slug}/.well-known/jwks.json               public
GET    /.well-known/oauth-protected-resource         public
POST   /t/{slug}/oauth/device_authorization          public
POST   /t/{slug}/oauth/token                         public
POST   /t/{slug}/oauth/revoke                        public
POST   /t/{slug}/oauth/introspect                    public
POST   /api/auth/device/lookup                       auth.self       -  # issue #14
POST   /api/auth/device/approve                      auth.self       STEP_UP_ADMIN  # issue #14: max_age 300 s
GET    /api/groups/folders                           groups.read     -  # issue #44, #47: the folders the caller may view
POST   /api/groups/folders                           groups.write    -  # issue #44, #47: create on the parent
GET    /api/groups/folders/{id}                      groups.read     -  # issue #44, #47: stem_view
PATCH  /api/groups/folders/{id}                      groups.write    -  # issue #44, #47: stem_admin
DELETE /api/groups/folders/{id}                      groups.write    -  # issue #44, #47: stem_admin
POST   /api/groups/folders/{id}/move                 groups.write    -  # issue #44, #47: stem_admin, create on the destination
POST   /api/groups/folders/{id}/copy                 groups.write    -  # issue #44, #47: stem_admin, create on the destination
GET    /api/groups/native                            groups.read     -  # issue #44, #47: the groups the caller may view
POST   /api/groups                                   groups.write    -  # issue #44, #47: create on the folder
GET    /api/groups/{id}                              groups.read     -  # issue #44, #47: view
PATCH  /api/groups/{id}                              groups.write    -  # issue #44, #47: admin
DELETE /api/groups/{id}                              groups.write    -  # issue #44, #47: admin
POST   /api/groups/{id}/move                         groups.write    -  # issue #44, #47: admin, create on the destination
POST   /api/groups/{id}/copy                         groups.write    -  # issue #44, #47: read, create on the destination
POST   /api/groups/{id}/restore                      groups.write    -  # issue #44, #47: admin
GET    /api/groups/{id}/members                      groups.read     -  # issue #45, #47: read
POST   /api/groups/{id}/members                      groups.write    -  # issue #45, #47: update, or optin for oneself
GET    /api/groups/{id}/members/{member}             groups.read     -  # issue #45, #47: read
DELETE /api/groups/{id}/members/{member}             groups.write    -  # issue #45, #47: update, or optout for oneself
POST   /api/groups/{id}/convert-to-composite         groups.write    -  # issue #45, #47: admin, read on the factors
PUT    /api/groups/{id}/composite                    groups.write    -  # issue #45, #47: admin, read on the factors
POST   /api/groups/engine/verify                     groups.admin    -  # issue #45
GET    /api/groups/engine/ops/{seq}                  groups.admin    -  # issue #45
GET    /api/groups/folders/{id}/privileges           groups.read     -  # issue #47: stem_admin
POST   /api/groups/folders/{id}/privileges           groups.write    -  # issue #47: stem_admin
GET    /api/groups/folders/{id}/privileges/effective groups.read     -  # issue #47: stem_view (own), stem_admin (another identity)
DELETE /api/groups/folders/{id}/privileges/{privilege_id} groups.write -  # issue #47: stem_admin
GET    /api/groups/{id}/privileges                   groups.read     -  # issue #47: admin
POST   /api/groups/{id}/privileges                   groups.write    -  # issue #47: admin
GET    /api/groups/{id}/privileges/effective         groups.read     -  # issue #47: view (own), admin (another identity)
DELETE /api/groups/{id}/privileges/{privilege_id}    groups.write    -  # issue #47: admin
GET    /api/groups/privileges/settings               groups.admin    -  # issue #47
PUT    /api/groups/privileges/settings               groups.admin    -  # issue #47
GET    /api/groups/folders/{id}/rules                groups.read     -  # issue #56: stem_admin
POST   /api/groups/folders/{id}/rules                groups.write    -  # issue #56: stem_admin, and admin on what the action touches
PUT    /api/groups/folders/{id}/rules/{rule_id}      groups.write    -  # issue #56: stem_admin, and admin on what the action touches
DELETE /api/groups/folders/{id}/rules/{rule_id}      groups.write    -  # issue #56: stem_admin
GET    /api/groups/{id}/rules                        groups.read     -  # issue #56: admin
POST   /api/groups/{id}/rules                        groups.write    -  # issue #56: admin, and admin on what the action touches
PUT    /api/groups/{id}/rules/{rule_id}              groups.write    -  # issue #56: admin, and admin on what the action touches
DELETE /api/groups/{id}/rules/{rule_id}              groups.write    -  # issue #56: admin
GET    /api/groups/rules/settings                    groups.admin    -  # issue #56
PUT    /api/groups/rules/settings                    groups.admin    -  # issue #56
PUT    /api/groups/users/{id}/identity               groups.admin    STEP_UP_POLICY  # issue #47
GET    /api/groups/pit/digests                       groups.admin    -  # issue #46
GET    /api/groups/pit/verify                        groups.admin    -  # issue #46
POST   /api/groups/pit/rebuild                       groups.admin    -  # issue #46
GET    /api/mfa/posture                              graph.read      -  # issue #109
POST   /api/groups/{id}/members:batch                groups.write    -  # issue #48: update, or optin / optout for oneself, per operation
POST   /api/groups:simulate                          groups.write    -  # issue #48: the privileges of the changes it simulates
GET    /api/identities/{identity_id}/groups          groups.read     -  # issue #48: only the groups the caller may read
GET    /api/openapi/groups.json                      auth.self       -  # issue #48
GET    /scim/v2/ServiceProviderConfig                groups.read     -  # issue #48: read-only SCIM server
GET    /scim/v2/ResourceTypes                        groups.read     -  # issue #48
GET    /scim/v2/Groups                               groups.read     -  # issue #48: only the groups the caller may read
GET    /scim/v2/Groups/{id}                          groups.read     -  # issue #48: read
GET    /scim/v2/Users                                groups.read     -  # issue #48
GET    /scim/v2/Users/{id}                           groups.read     -  # issue #48
GET    /api/groups/object-types                      groups.read     -  # issue #50: the object type vocabulary
GET    /api/groups/services                          groups.read     -  # issue #50: the services the caller's groups grant (stem_view, view)
GET    /api/groups/attr-defs                         groups.read     -  # issue #50: the definitions the caller may view (attr_view)
POST   /api/groups/attr-defs                         groups.write    -  # issue #50: create on the folder
GET    /api/groups/attr-defs/{id}                    groups.read     -  # issue #50: attr_view
PATCH  /api/groups/attr-defs/{id}                    groups.write    -  # issue #50: attr_admin
DELETE /api/groups/attr-defs/{id}                    groups.write    -  # issue #50: attr_admin
GET    /api/groups/attr-defs/{id}/actions            groups.read     -  # issue #50: attr_view
POST   /api/groups/attr-defs/{id}/actions            groups.write    -  # issue #50: attr_admin
DELETE /api/groups/attr-defs/{id}/actions/{action_id} groups.write   -  # issue #50: attr_admin
PUT    /api/groups/attr-defs/{id}/actions/{action_id}/implies groups.write -  # issue #50: attr_admin
GET    /api/groups/attr-defs/{id}/privileges         groups.read     -  # issue #50: attr_admin
POST   /api/groups/attr-defs/{id}/privileges         groups.write    -  # issue #50: attr_admin
GET    /api/groups/attr-defs/{id}/privileges/effective groups.read   -  # issue #50: attr_view (own), attr_admin (another identity)
DELETE /api/groups/attr-defs/{id}/privileges/{privilege_id} groups.write -  # issue #50: attr_admin
GET    /api/groups/attr-names                        groups.read     -  # issue #50: attr_view on the definition
POST   /api/groups/attr-names                        groups.write    -  # issue #50: attr_admin on the definition
GET    /api/groups/attr-names/{id}                   groups.read     -  # issue #50: attr_view
PATCH  /api/groups/attr-names/{id}                   groups.write    -  # issue #50: attr_admin
DELETE /api/groups/attr-names/{id}                   groups.write    -  # issue #50: attr_admin
PUT    /api/groups/attr-names/{id}/implies           groups.write    -  # issue #50: attr_admin
GET    /api/groups/attr-assignments                  groups.read     -  # issue #50: attr_read and the owner's read privilege (filtered)
POST   /api/groups/attr-assignments                  groups.write    -  # issue #50: attr_update and the owner's update privilege (attr_optin on oneself)
GET    /api/groups/attr-assignments/{id}             groups.read     -  # issue #50: attr_read and the owner's read privilege
PATCH  /api/groups/attr-assignments/{id}             groups.write    -  # issue #50: attr_update and the owner's update privilege
DELETE /api/groups/attr-assignments/{id}             groups.write    -  # issue #50: attr_update and the owner's update privilege (attr_optout on oneself)
PUT    /api/groups/attr-assignments/{id}/values      groups.write    -  # issue #50: attr_update and the owner's update privilege
GET    /api/groups/{id}/object-types                 groups.read     -  # issue #50: view (lint findings need read)
PUT    /api/groups/{id}/object-types                 groups.write    -  # issue #50: group_attr_update
GET    /api/groups/folders/{id}/object-types         groups.read     -  # issue #50: stem_view
PUT    /api/groups/folders/{id}/object-types         groups.write    -  # issue #50: stem_attr_update
GET    /api/auth/session                             auth.self       -
POST   /api/auth/logout                              auth.self       -
GET    /api/auth/sessions                            auth.self       -
GET    /api/auth/step-up                             auth.self       -
DELETE /api/auth/sessions/{session_id}               auth.self       -  (another user's: admin.sessions.revoke + STEP_UP_ADMIN in the handler)
GET    /api/auth/discover                            public
GET    /api/auth/login                               public
GET    /api/auth/oidc/{connection_id}/callback       public
GET    /api/auth/saml/{connection_id}/metadata       public
POST   /api/auth/saml/{connection_id}/acs            public
GET    /api/auth/cas/{connection_id}/callback        public
POST   /api/auth/wsfed/{connection_id}/callback      public
GET    /t/{slug}/bootstrap                           public
GET    /api/admin/users                              admin.read      -  # issue #16
POST   /api/admin/users/{user_id}/disable            admin.users.disable STEP_UP_ADMIN  # issue #16
GET    /api/admin/idp-connections                    admin.read      -  # issue #16
POST   /api/admin/idp-connections/{connection_id}/activate admin.change.request STEP_UP_ADMIN  # issue #16
GET    /api/admin/change-requests                    admin.read      -  # issue #16
POST   /api/admin/change-requests                    admin.change.request STEP_UP_ADMIN  # issue #16
GET    /api/admin/change-requests/{change_id}        admin.read      -  # issue #16
POST   /api/admin/change-requests/{change_id}/approve admin.change.approve STEP_UP_ADMIN  # issue #16
POST   /api/admin/change-requests/{change_id}/reject admin.change.approve -  # issue #16
POST   /api/admin/change-requests/{change_id}/cancel admin.change.request -  # issue #16
POST   /api/admin/change-requests/{change_id}/apply  admin.change.approve STEP_UP_ADMIN  # issue #16
GET    /api/admin/notifications                      admin.read      -  # issue #16
GET    /api/admin/api-clients                        admin.read      -  # issue #15
GET    /api/admin/api-clients/{client_id}            admin.read      -  # issue #15
GET    /api/admin/recovery                           admin.read      -  # issue #16
POST   /api/admin/recovery/{recovery_id}/cancel      admin.change.request -  # issue #16
GET    /api/admin/api-clients                        admin.read      -  # issue #16
POST   /public/t/{slug}/claim/start                 public  # issue #69: the guest's claim, by link token, cookie and key proof
POST   /public/t/{slug}/claim/verify/send            public
POST   /public/t/{slug}/claim/verify/check           public
GET    /public/t/{slug}/claim/status                 public
POST   /public/t/{slug}/claim/existing-account       public
GET    /public/t/{slug}/claim/terms                  public
POST   /public/t/{slug}/claim/terms/accept           public
POST   /public/t/{slug}/claim/consent                public
POST   /public/t/{slug}/claim/credential             public
POST   /public/t/{slug}/claim/resend                 public
GET    /api/admin/platform-health                    admin.read      -  # issue #303
POST   /api/auth/break-glass/options                 public
POST   /api/auth/break-glass/verify                  public
GET    /api/admin/break-glass                        admin.read      -  # issue #17
POST   /api/admin/break-glass/registration/options   admin.change.request STEP_UP_ADMIN  # issue #17
POST   /api/admin/break-glass/registration/verify    admin.change.request STEP_UP_ADMIN  # issue #17
POST   /api/admin/break-glass/actions/{action}       breakglass.recover -  # issue #17
POST   /api/admin/break-glass/uses/{use_id}/attest   admin.change.request -  # issue #17
POST   /public/t/{slug}/guest/renewal-request        public  # issue #74: the guest's "request renewal" link, always 202
GET    /public/t/{slug}/register/sponsors           public  # issue #66: sponsor names (no emails), at least 2 letters, rate-limited
POST   /public/t/{slug}/register                     public  # issue #66: self-registration, bot challenge, 5 per IP per hour, always 202
`

type designRoute struct {
	method, pattern string
	public          bool
	perm            auth.Permission
	stepUp          string // "", STEP_UP_POLICY or STEP_UP_ADMIN
}

// stepUps maps the table's step-up column to the requirement it names.
var stepUps = map[string]*auth.AuthnRequirement{"": nil, "STEP_UP_POLICY": &auth.StepUpPolicy, "STEP_UP_ADMIN": &auth.StepUpAdmin}

func parseDesignRoutes(t *testing.T) []designRoute {
	t.Helper()
	var out []designRoute
	for _, line := range strings.Split(designRoutes, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		r := designRoute{method: f[0], pattern: f[1]}
		if f[2] == "public" {
			r.public = true
		} else {
			if len(f) < 4 {
				t.Fatalf("bad table line %q", line)
			}
			r.perm = auth.Permission(f[2])
			if strings.HasPrefix(f[3], "STEP_UP_") {
				r.stepUp = f[3]
			}
			if _, ok := stepUps[r.stepUp]; !ok {
				t.Fatalf("unknown step-up %q in table line %q", f[3], line)
			}
		}
		out = append(out, r)
	}
	return out
}

// TestRoutesMatchDesignTable: the registered routes are exactly the design
// table, with the same permission and step-up requirement.
func TestRoutesMatchDesignTable(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	table := map[string]designRoute{}
	for _, r := range parseDesignRoutes(t) {
		table[r.method+" "+r.pattern] = r
	}
	seen := map[string]bool{}
	for _, rt := range srv.Routes() {
		k := rt.Method + " " + rt.Pattern
		seen[k] = true
		d, ok := table[k]
		if !ok {
			t.Errorf("%s is registered but not in the design table", k)
			continue
		}
		if rt.Public != d.public || rt.Perm != d.perm {
			t.Errorf("%s: public=%t perm=%q, design public=%t perm=%q", k, rt.Public, rt.Perm, d.public, d.perm)
		}
		if want := stepUps[d.stepUp]; (rt.Authn == nil) != (want == nil) || (want != nil && *rt.Authn != *want) {
			t.Errorf("%s: step-up %v, design %q", k, rt.Authn, d.stepUp)
		}
	}
	for k := range table {
		if !seen[k] {
			t.Errorf("%s is in the design table but not registered", k)
		}
	}
}

// rbacRoles are the principals of the matrix: one per role, each signed in
// with a fresh phishing-resistant context (so every role a principal holds
// is active and every step-up requirement is met: the matrix tests the
// permission column alone; role activation and step-up have their own tests).
var rbacRoles = []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyAdmin,
	auth.RoleTenantAdmin, auth.RoleBreakGlass}

// TestRBACRouteMatrix (design §19 PR5 api/rbac_routes_test): for every
// route of the design table and every role, the expected status: 401
// without a session, 403 when the role lacks the route's permission, and
// otherwise anything but 401/403 (the handler ran). break_glass is never
// active under an IdP sign-in, so it is refused everything but the
// session's own routes.
func TestRBACRouteMatrix(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	logins := map[auth.Role]authtest.Login{}
	for _, r := range rbacRoles {
		logins[r] = signIn(t, f.DB, f.B.ID, authtest.User{Email: string(r) + "@b.example", Roles: []auth.Role{r}},
			authtest.Phr, storetest.Now)
	}
	routes := map[string]RouteInfo{}
	for _, rt := range srv.Routes() {
		routes[rt.Method+" "+rt.Pattern] = rt
	}
	for _, d := range parseDesignRoutes(t) {
		rt, ok := routes[d.method+" "+d.pattern]
		if !ok || d.public || d.pattern == "/api/auth/logout" {
			continue // public routes: TestAllRoutesRequireAuth; logout ends the role's session
		}
		t.Run(d.method+" "+d.pattern, func(t *testing.T) {
			if rec := serve(h, withHeader(routeRequest(rt, f.B), "X-Test-Anonymous", "1")); rec.Code != http.StatusUnauthorized {
				t.Errorf("anonymous: %d, want 401", rec.Code)
			}
			for _, role := range rbacRoles {
				req := routeRequest(rt, f.B)
				logins[role].Apply(req)
				rec := serve(h, req)
				// auth.self: any principal, whatever its roles
				allowed := d.perm == auth.PermAuthenticated ||
					(role != auth.RoleBreakGlass && containsPerm(auth.RolePermissions(role), d.perm))
				// a group route's handler may still refuse for want of the folder's or
				// group's privilege (403 privilege_required, issue #47): the handler ran
				privDenied := rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), `"privilege_required"`)
				switch {
				case allowed && !privDenied && (rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden):
					t.Errorf("%s: %d %.200s, want the handler to run", role, rec.Code, rec.Body.String())
				case !allowed && rec.Code != http.StatusForbidden:
					t.Errorf("%s: %d %.200s, want 403", role, rec.Code, rec.Body.String())
				}
			}
		})
	}
}

// TestRevokeApplyNeedsGrantsRevoke: a dry run needs graph.read; applying
// needs grants.revoke (policy admins only) and a fresh phishing-resistant
// sign-in (§16.2, checked in the handler because it depends on the body).
func TestRevokeApplyNeedsGrantsRevoke(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	edge := f.B.IDs["edge:0"]
	for _, tc := range []struct {
		role   auth.Role
		ctx    authtest.Ctx
		status int
		err    string
	}{
		{auth.RoleViewer, authtest.Phr, 403, "forbidden"},
		{auth.RoleOperator, authtest.Phr, 403, "forbidden"},
		{auth.RoleTenantAdmin, authtest.Phr, 403, "forbidden"},
		{auth.RolePolicyAdmin, authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, 401, "step_up_required"},
		{auth.RolePolicyAdmin, authtest.Phr, 200, ""},
	} {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: fmt.Sprintf("%s-%d@b.example", tc.role, tc.status),
			Roles: []auth.Role{tc.role}}, tc.ctx, storetest.Now)
		dry := httptest.NewRequest(http.MethodPost, "/api/least-privilege/revoke", strings.NewReader(fmt.Sprintf(`{"edge_id":%d}`, edge)))
		dry.Header.Set("Content-Type", "application/json")
		l.Apply(dry)
		if rec := serve(h, dry); rec.Code != http.StatusOK && tc.role != auth.RolePolicyAdmin {
			t.Errorf("%s dry run: %d", tc.role, rec.Code)
		}
		apply := httptest.NewRequest(http.MethodPost, "/api/least-privilege/revoke",
			strings.NewReader(fmt.Sprintf(`{"edge_id":%d,"dry_run":false}`, edge)))
		apply.Header.Set("Content-Type", "application/json")
		l.Apply(apply)
		rec := serve(h, apply)
		if rec.Code != tc.status || (tc.err != "" && !strings.Contains(rec.Body.String(), tc.err)) {
			t.Errorf("%s apply: %d %.200s, want %d %s", tc.role, rec.Code, rec.Body.String(), tc.status, tc.err)
		}
	}
}

func withHeader(r *http.Request, k, v string) *http.Request {
	r.Header.Set(k, v)
	return r
}

func containsPerm(ps []auth.Permission, p auth.Permission) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

// TestConnectionConfigNeedsStepUp: editing a connection's config can point
// its credential at another host or widen its write scope, so it needs the
// same fresh phishing-resistant sign-in as setting the credential.
func TestConnectionConfigNeedsStepUp(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := authtest.User{Email: "conn-admin@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}
	stale := signIn(t, f.DB, f.B.ID, admin, authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	body := `{"base_url":"https://attacker.example"}`
	for _, path := range []string{"/api/connections/x/config", "/api/connections/x/credential"} {
		method := map[bool]string{true: "PATCH", false: "PUT"}[strings.HasSuffix(path, "config")]
		if rec := serve(h, authed(stale, method, path, body)); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
			t.Errorf("%s %s with a 20-minute-old sign-in: %d %s", method, path, rec.Code, rec.Body.String())
		}
	}
	fresh := signIn(t, f.DB, f.B.ID, authtest.User{Email: "conn-admin2@b.example", Roles: admin.Roles}, authtest.Phr, storetest.Now)
	if rec := serve(h, authed(fresh, "PATCH", "/api/connections/x/config", body)); rec.Code == 401 || rec.Code == 403 {
		t.Errorf("PATCH config with a fresh sign-in: %d %s", rec.Code, rec.Body.String())
	}
}

// TestAgentRoutesNeedStepUp: an enrolment code puts a host inside the customer
// network on the path to the directory, so issuing one and revoking an agent
// need a fresh phishing-resistant sign-in; viewers may only list.
func TestAgentRoutesNeedStepUp(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := authtest.User{Email: "agent-admin@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}
	stale := signIn(t, f.DB, f.B.ID, admin, authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	for _, c := range []struct{ method, path string }{{"POST", "/api/agents"}, {"POST", "/api/agents/" + missingUUID + "/revoke"}} {
		if rec := serve(h, authed(stale, c.method, c.path, `{"name":"dc-agent"}`)); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
			t.Errorf("%s %s with a 20-minute-old sign-in: %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	if rec := serve(h, authed(stale, "GET", "/api/agents", "")); rec.Code != 200 {
		t.Errorf("listing needs no step-up: %d %s", rec.Code, rec.Body.String())
	}
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "agent-viewer@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	if rec := serve(h, authed(viewer, "POST", "/api/agents", `{"name":"dc-agent"}`)); rec.Code != 403 {
		t.Errorf("a viewer issued an enrolment code: %d %s", rec.Code, rec.Body.String())
	}
	fresh := signIn(t, f.DB, f.B.ID, authtest.User{Email: "agent-admin2@b.example", Roles: admin.Roles}, authtest.Phr, storetest.Now)
	if rec := serve(h, authed(fresh, "POST", "/api/agents", `{"name":"dc-agent"}`)); rec.Code != 201 {
		t.Errorf("a fresh sign-in could not issue a code: %d %s", rec.Code, rec.Body.String())
	}
}
