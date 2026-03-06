package sbom_scanning

import (
	"context"
	"fmt"
	"log/slog"

	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/sbom_scanning/pkg/types/memory_service"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

func Scan(ctx context.Context, targetName string, data []byte, globalOptions *flag.GlobalOptions) (*types.Report, error) {
	if globalOptions == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("global options"))
	}

	opts := flag.Options{
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
			Target:      targetName,
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

	runner, err := artifact.NewRunner(
		ctx,
		opts,
		artifact.TargetSBOM,
		artifact.WithInitializeService(memory_service.New(targetName, data)),
	)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("trivy artifact new runner: %w", err))
	}
	defer func() {
		if err := runner.Close(ctx); err != nil {
			slog.WarnContext(
				motmedelContext.WithError(
					ctx,
					motmedelErrors.NewWithTrace(fmt.Errorf("trivy artifact runner close: %w", err)),
				),
				"An error occurred when closing the artifact runner.",
			)
		}
	}()

	report, err := runner.ScanSBOM(ctx, opts)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("trivy artifact runner scan sbom: %w", err))
	}

	report, err = runner.Filter(ctx, opts, report)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("trivy artifact runner filter: %w", err))
	}

	return &report, nil
}
