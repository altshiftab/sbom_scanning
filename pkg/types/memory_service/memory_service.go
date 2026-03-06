package memory_service

import (
	"context"
	"fmt"

	"github.com/Motmedel/utils_go/pkg/errors"
	"github.com/altshiftab/sbom_scanning/pkg/types/memory_artifact"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/scan/local"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

// New builds a scan.Service that uses an in-memory SBOM artifact.
func New(name string, data []byte) artifact.InitializeScanService {
	return func(_ context.Context, conf artifact.ScannerConfig) (scan.Service, func(), error) {
		c, cleanupCache, err := cache.New(conf.CacheOptions)
		if err != nil {
			return scan.Service{}, nil, errors.NewWithTrace(fmt.Errorf("trivy cache new: %w", err))
		}

		app := applier.NewApplier(c)
		osScanner := ospkg.NewScanner()
		langScanner := langpkg.NewScanner()
		vulnClient := vulnerability.NewClient(db.Config{})
		service := local.NewService(app, osScanner, langScanner, vulnClient)

		art := &memory_artifact.Artifact{
			Name:   name,
			Data:   data,
			Cache:  c,
			Option: conf.ArtifactOption,
		}

		return scan.NewService(service, art), cleanupCache, nil
	}
}
