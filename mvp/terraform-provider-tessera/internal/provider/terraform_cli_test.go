package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// The same lifecycle through the real terraform CLI (terraform-plugin-testing): plan, apply, refresh, import, destroy, with
// Terraform's own checks that a plan after apply is empty. Needs TF_ACC=1 and a terraform binary (TF_ACC_TERRAFORM_PATH, the PATH,
// or a download by the plugin-testing library) in addition to the server of testserver_test.go. The protocol tests in
// acceptance_test.go cover the same ground without the binary.

func TestAccCLI_ReviewSchedule(t *testing.T) {
	ts := startTestServer(t)
	hcl := func(name string, duration int) string {
		return fmt.Sprintf(`
provider "tessera" {
  endpoint         = %q
  tenant           = %q
  client_id        = %q
  private_key_file = %q
  key_id           = %q
}

resource "tessera_review_schedule" "q" {
  name          = %q
  recurrence    = "quarterly"
  first_run_at  = "2027-01-01T00:00:00Z"
  duration_days = %d
}
`, ts.URL, ts.Tenant, ts.BearerID, ts.KeyFile, ts.KeyID, name, duration)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"tessera": providerserver.NewProtocol6WithError(New("test")()),
		},
		Steps: []resource.TestStep{
			{Config: hcl("cli quarterly", 14), Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("tessera_review_schedule.q", "name", "cli quarterly"),
				resource.TestCheckResourceAttr("tessera_review_schedule.q", "close_out", "revoke"),
				resource.TestCheckResourceAttrSet("tessera_review_schedule.q", "id"),
				resource.TestCheckResourceAttrSet("tessera_review_schedule.q", "next_run_at"),
			)},
			{Config: hcl("cli quarterly renamed", 21), Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("tessera_review_schedule.q", "name", "cli quarterly renamed"),
				resource.TestCheckResourceAttr("tessera_review_schedule.q", "duration_days", "21"),
			)},
			{ResourceName: "tessera_review_schedule.q", ImportState: true, ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"first_run_at"}},
		},
	})
}
