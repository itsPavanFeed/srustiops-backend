// terraform-provider-srustiops manages a SrustiOps tenant's configuration
// as code from OpenTofu or Terraform.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/itsPavanFeed/srustiops-backend/terraform-provider-srustiops/internal/provider"
)

var version = "dev" // set with -ldflags "-X main.version=..."

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.opentofu.org/itspavanfeed/srustiops",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
