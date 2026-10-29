terraform {
  required_providers {
    tessera = {
      source = "nischalravi/tessera"
    }
  }
}

# Every value can come from the environment instead (TESSERA_ENDPOINT, TESSERA_TENANT, TESSERA_CLIENT_ID,
# TESSERA_PRIVATE_KEY_FILE, TESSERA_KEY_ID, TESSERA_DPOP), which keeps them out of the configuration.
provider "tessera" {
  endpoint         = "https://tessera.example.com"
  tenant           = "larkspur"
  client_id        = "tsc_3bkinseovjluwkan"
  private_key_file = "/etc/terraform/tessera-client-key.pem"
  key_id           = "ci-1"
  dpop             = true # the client was registered with dpop_required
}
