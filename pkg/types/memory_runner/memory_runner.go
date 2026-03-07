package memory_runner

import (
	"context"
	"fmt"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/sbom_scanning/pkg/types/memory_service"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	fartifact "github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Runner struct {
	trivyRunner artifact.Runner
	options     flag.Options
}

func (r *Runner) Scan(ctx context.Context, targetName string, data []byte) (*types.Report, error) {
	if len(data) == 0 {
		return nil, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	scannerConfig := artifact.ScannerConfig{
		Target:       targetName,
		CacheOptions: r.options.CacheOpts(),
		ArtifactOption: fartifact.Option{
			Offline: r.options.OfflineScan,
		},
	}

	initService := memory_service.New(targetName, data)
	service, cleanup, err := initService(ctx, scannerConfig)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("initialize scan service: %w", err))
	}
	defer cleanup()

	report, err := service.ScanArtifact(ctx, r.options.ScanOpts())
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("scan artifact: %w", err))
	}

	report, err = r.trivyRunner.Filter(ctx, r.options, report)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("filter: %w", err))
	}

	return &report, nil
}

func (r *Runner) Close(ctx context.Context) error {
	return r.trivyRunner.Close(ctx)
}

func New(ctx context.Context, globalOptions *flag.GlobalOptions) (*Runner, error) {
	if globalOptions == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("global options"))
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	options := flag.Options{
		GlobalOptions: *globalOptions,
		DBOptions: flag.DBOptions{
			SkipDBUpdate:     false,
			SkipJavaDBUpdate: false,
		},
		PackageOptions: flag.PackageOptions{
			PkgTypes:         types.PkgTypes,
			PkgRelationships: ftypes.Relationships,
		},
		ScanOptions: flag.ScanOptions{
			Scanners:    types.Scanners{types.VulnerabilityScanner},
			OfflineScan: true,
		},
		ReportOptions: flag.ReportOptions{
			Format: types.FormatJSON,
			Severities: []dbTypes.Severity{
				dbTypes.SeverityUnknown,
				dbTypes.SeverityLow,
				dbTypes.SeverityMedium,
				dbTypes.SeverityHigh,
				dbTypes.SeverityCritical,
			},
		},
	}

	trivyRunner, err := artifact.NewRunner(ctx, options, artifact.TargetSBOM)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("trivy artifact new runner: %w", err))
	}

	return &Runner{
		trivyRunner: trivyRunner,
		options:     options,
	}, nil
}
