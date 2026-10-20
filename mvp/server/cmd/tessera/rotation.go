package main

import (
	"context"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/rotation"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// seedRotationDemo gives the demo tenant a simulated provider and rotation
// policies for the demo credentials, so the Rotate action, the jobs list and
// the vendor-compromised flow work on the dev stack. The simulated adapter
// never calls anything: config refuses it in prod (and seeding does too).
// Kinds with no API to rotate through (personal access tokens, GitHub App
// keys, key pairs, passwords) get age-only policies: the owner is told.
func seedRotationDemo(ctx context.Context, st *store.DB, tenant tenancy.ID, clock timeutil.Clock) error {
	svc := &rotation.Service{Env: config.Dev, AllowFake: true}
	now := clock()
	return st.InTenant(audit.WithSystemActor(ctx, "seed"), tenant, func(tx *store.TenantTx) error {
		for _, name := range []string{"simulated-provider", "simulated-vault"} {
			if _, _, err := svc.PutAdapter(tx, rotation.AdapterInput{Name: name, Type: rotation.TypeFake}, "seed", now); err != nil {
				return err
			}
		}
		sim, vault := "simulated-provider", "simulated-vault"
		for _, p := range []rotation.PolicyInput{
			{Kind: "access_key", MaxAgeDays: 90, GraceHours: 24, Adapter: &sim, Destination: &vault, DestPath: "kv/{system}/{name}"},
			{Kind: "api_token", MaxAgeDays: 60, GraceHours: 24, Adapter: &sim, Destination: &vault, DestPath: "kv/{system}/{name}"},
			{Kind: "api_key", MaxAgeDays: 90, GraceHours: 24, Adapter: &sim, Destination: &vault, DestPath: "kv/{system}/{name}"},
			{Kind: "deploy_key", MaxAgeDays: 180, GraceHours: 24, Adapter: &sim, Destination: &vault, DestPath: "kv/{system}/{name}"},
			{Kind: "pat", MaxAgeDays: 90},
			{Kind: "github_app", MaxAgeDays: 180},
			{Kind: "keypair", MaxAgeDays: 180},
			{Kind: "password", MaxAgeDays: 90},
		} {
			if _, _, err := svc.PutPolicy(tx, p, "seed", now); err != nil {
				return err
			}
		}
		return nil
	})
}
