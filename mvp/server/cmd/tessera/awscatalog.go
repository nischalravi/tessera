package main

import (
	"github.com/nischalravi/tessera/mvp/server/internal/api"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
)

// awsCatalogLoader returns the loader of the AWS action catalog the evaluator
// routes run against, or nil (they answer 503) when no catalog directory is
// configured (TESSERA_AWS_CATALOG_DIR).
func awsCatalogLoader(cfg *config.Config) func() (*api.AWSCatalog, error) {
	if cfg.AWSCatalogDir == "" {
		return nil
	}
	return api.CatalogFromDir(cfg.AWSCatalogDir, cfg.AWSCatalogVersion)
}
