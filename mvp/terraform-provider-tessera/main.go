// terraform-provider-tessera manages Tessera configuration as code.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/nischalravi/tessera/mvp/terraform-provider-tessera/internal/provider"
)

// version is set at release time (-ldflags "-X main.version=1.2.3").
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers such as delve")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/nischalravi/tessera",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
