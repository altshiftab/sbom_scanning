// Command sbom_scanning lists the known vulnerabilities of the packages in an SBOM — given as files, piped in, or
// generated on the spot from a local container image — against a Trivy vulnerability database, which it fetches when
// it has none.
package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	sbomScanningFinding "github.com/altshiftab/sbom_scanning/pkg/types/finding"
	sbomScanner "github.com/altshiftab/sbom_scanning/pkg/types/scanner"
	argumentParser "github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	argumentParserErrors "github.com/altshiftab/utils_go/pkg/cli/argument_parser/errors"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	altshiftSbom "github.com/altshiftab/utils_go/pkg/sbom"
	altshiftSbomImage "github.com/altshiftab/utils_go/pkg/sbom/image"
	altshiftSbomTypes "github.com/altshiftab/utils_go/pkg/sbom/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

const (
	exitClean = 0
	exitError = 1
	exitUsage = 2
	// exitFindings is the exit status when --fail-on names a severity and a finding reaches it.
	exitFindings = 3

	formatTable = "table"
	formatJson  = "json"

	stdinName = "-"
)

const description = "List the known vulnerabilities of the packages in an SBOM against a Trivy vulnerability " +
	"database. SBOMs come from the files named, from standard input when none is (or one is \"-\"), or from a " +
	"local container image (--image), described the way the sbom command does it. The database is Trivy's own " +
	"(reused from Trivy's cache directory when present) and is downloaded when missing or when asked."

var errNothingToScan = errors.New("nothing to scan: give SBOM files, pipe one in, or name an --image")

// severityRank orders severities from unknown to critical, for filtering and sorting.
var severityRank = map[string]int{
	dbTypes.SeverityUnknown.String():  0,
	dbTypes.SeverityLow.String():      1,
	dbTypes.SeverityMedium.String():   2,
	dbTypes.SeverityHigh.String():     3,
	dbTypes.SeverityCritical.String(): 4,
}

type arguments struct {
	sboms       []string
	image       string
	dockerfile  string
	database    string
	update      bool
	format      string
	minSeverity string
	fixedOnly   bool
	shippedOnly bool
	failOn      string
	podman      string
}

func newParser(args *arguments, output io.Writer) *argumentParser.Parser {
	severities := dbTypes.SeverityNames
	return &argumentParser.Parser{
		ProgramName: "sbom_scanning",
		Description: description,
		Output:      output,
		Options: []option.Option{
			option.WithMetavar(option.NewStringOption(0, "image", "a local container image to describe and scan, as podman knows it (e.g. localhost/app:latest)", false, &args.image), "REFERENCE"),
			option.WithMetavar(option.NewStringOption(0, "dockerfile", "with --image: the Dockerfile the image was built from, whose build-stage images are scanned as well", false, &args.dockerfile), "PATH"),
			option.WithMetavar(option.WithDefault(option.NewStringOption(0, "database", "the directory holding the Trivy database (trivy.db)", false, &args.database), defaultDatabaseDir()), "DIR"),
			option.NewBoolOption(0, "update", "download the latest database before scanning, even when one is present", false, &args.update),
			option.WithChoices(option.WithDefault(option.NewStringOption(0, "format", "how to print the findings", false, &args.format), formatTable), formatTable, formatJson),
			option.WithChoices(option.WithDefault(option.NewStringOption(0, "min-severity", "leave out findings below this severity", false, &args.minSeverity), dbTypes.SeverityUnknown.String()), severities...),
			option.NewBoolOption(0, "fixed-only", "leave out findings without a fixed version", false, &args.fixedOnly),
			option.NewBoolOption(0, "shipped-only", "leave out findings in components the SBOM marks as excluded (build images, development dependencies)", false, &args.shippedOnly),
			option.WithChoices(option.WithMetavar(option.NewStringOption(0, "fail-on", "exit with status 3 when a finding of this severity or above remains", false, &args.failOn), "SEVERITY"), severities...),
			option.WithMetavar(option.WithDefault(option.NewStringOption(0, "podman", "the podman executable to read images with", false, &args.podman), "podman"), "PATH"),
		},
		Positionals: []option.Option{
			option.WithNargs(option.WithMetavar(option.NewStringsOption(0, "", "SBOM files to scan (CycloneDX JSON or XML, SPDX JSON); \"-\" is standard input", false, &args.sboms), "SBOM"), option.NargsAny),
		},
		DisableAbbrev: true,
	}
}

// input is one SBOM to scan and where it came from.
type input struct {
	name string
	data []byte
}

// report is what one input yielded, as printed in JSON.
type report struct {
	Source   string                         `json:"source"`
	Findings []*sbomScanningFinding.Finding `json:"findings"`
}

// run does what the command line asks and returns the exit status and, for a failure, the error to report.
func run(ctx context.Context, argv []string, stdin io.Reader, stdinIsTerminal bool, stdout, stderr io.Writer, registry *url.URL, now func() time.Time) (int, error) {
	args := &arguments{}
	parser := newParser(args, stdout)
	if err := parser.Validate(); err != nil {
		return exitError, altshiftErrors.New(fmt.Errorf("parser validate: %w", err))
	}
	if err := parser.ParseArgs(argv); err != nil {
		if errors.Is(err, argumentParserErrors.ErrHelp) {
			return exitClean, nil
		}
		fmt.Fprint(stderr, parser.FormatError(err))
		return exitUsage, nil
	}

	inputs, err := readInputs(ctx, args, stdin, stdinIsTerminal, stderr)
	if err != nil {
		return exitError, err
	}
	// Updating the database is a thing to ask for on its own.
	if len(inputs) == 0 && !args.update {
		fmt.Fprint(stderr, parser.FormatError(errNothingToScan))
		return exitUsage, nil
	}

	if err := ensureDatabase(ctx, args, registry, now, stderr); err != nil {
		return exitError, err
	}
	if len(inputs) == 0 {
		return exitClean, nil
	}

	vulnerabilityScanner, err := sbomScanner.New(args.database)
	if err != nil {
		return exitError, altshiftErrors.New(fmt.Errorf("scanner new: %w", err), args.database)
	}
	defer func() { _ = vulnerabilityScanner.Close() }()

	failed := false
	for i, in := range inputs {
		findings, err := vulnerabilityScanner.Scan(in.data)
		if err != nil {
			return exitError, altshiftErrors.New(fmt.Errorf("scan %s: %w", in.name, err), in.name)
		}
		findings = filterFindings(findings, args)
		sortFindings(findings)

		switch args.format {
		case formatJson:
			if err := writeJson(stdout, &report{Source: in.name, Findings: findings}); err != nil {
				return exitError, err
			}
		default:
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			if len(inputs) > 1 || in.name != stdinName {
				fmt.Fprintf(stdout, "%s\n", in.name)
			}
			writeTable(stdout, findings)
		}

		if args.failOn != "" && slices.ContainsFunc(findings, func(f *sbomScanningFinding.Finding) bool {
			return severityRank[findingSeverity(f)] >= severityRank[args.failOn]
		}) {
			failed = true
		}
	}

	if failed {
		return exitFindings, nil
	}
	return exitClean, nil
}

// readInputs gathers the SBOMs to scan: the files named (or standard input), and the description of the image.
func readInputs(ctx context.Context, args *arguments, stdin io.Reader, stdinIsTerminal bool, stderr io.Writer) ([]*input, error) {
	var inputs []*input

	sboms := args.sboms
	// Piped input is scanned without being named, so that `sbom ... | sbom_scanning` just works.
	if len(sboms) == 0 && args.image == "" && !stdinIsTerminal {
		sboms = []string{stdinName}
	}
	for _, name := range sboms {
		var data []byte
		var err error
		if name == stdinName {
			data, err = io.ReadAll(stdin)
		} else {
			data, err = os.ReadFile(name) //nolint:gosec // G304: reading the files the user named is the command's purpose
		}
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("read %s: %w", name, err), name)
		}
		// Nothing on standard input is nothing to scan, not an empty SBOM.
		if name == stdinName && len(bytes.TrimSpace(data)) == 0 {
			continue
		}
		inputs = append(inputs, &input{name: name, data: data})
	}

	if args.image != "" {
		sources := &altshiftSbom.Sources{Image: args.image}
		if args.dockerfile != "" {
			data, err := os.ReadFile(args.dockerfile) //nolint:gosec // G304: the Dockerfile the user named
			if err != nil {
				return nil, altshiftErrors.NewWithTrace(fmt.Errorf("read %s: %w", args.dockerfile, err), args.dockerfile)
			}
			sources.Dockerfile = data
		}
		data, warnings, err := altshiftSbom.DescribeJson(ctx, &altshiftSbomImage.Store{Podman: args.podman}, sources)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("describe %s: %w", args.image, err), args.image)
		}
		for _, warning := range warnings {
			fmt.Fprintf(stderr, "sbom_scanning: warning: %s\n", warning)
		}
		inputs = append(inputs, &input{name: args.image, data: data})
	}

	return inputs, nil
}

// ensureDatabase makes sure a database is there to scan with: it downloads one when asked or when none exists, and
// points out one that has grown old.
func ensureDatabase(ctx context.Context, args *arguments, registry *url.URL, now func() time.Time, stderr io.Writer) error {
	_, statErr := os.Stat(filepath.Join(args.database, databaseFileName))
	missing := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !missing {
		return altshiftErrors.NewWithTrace(fmt.Errorf("stat database: %w", statErr), args.database)
	}

	if args.update || missing {
		if missing && !args.update {
			fmt.Fprintf(stderr, "sbom_scanning: no database in %s\n", args.database)
		}
		if err := downloadDatabase(ctx, registry, args.database, stderr); err != nil {
			return fmt.Errorf("download database: %w", err)
		}
		return nil
	}

	if age := databaseAge(args.database, now()); age > databaseStaleAfter {
		fmt.Fprintf(stderr, "sbom_scanning: warning: the database is %d days old; pass --update to refresh it\n", int(age.Hours()/24))
	}
	return nil
}

func findingSeverity(f *sbomScanningFinding.Finding) string {
	if f == nil || f.Vulnerability == nil || f.Vulnerability.Severity == "" {
		return dbTypes.SeverityUnknown.String()
	}
	return f.Vulnerability.Severity
}

// filterFindings applies --min-severity, --fixed-only and --shipped-only.
func filterFindings(findings []*sbomScanningFinding.Finding, args *arguments) []*sbomScanningFinding.Finding {
	var kept []*sbomScanningFinding.Finding
	for _, f := range findings {
		if f == nil || f.Vulnerability == nil || f.Package == nil {
			continue
		}
		if severityRank[findingSeverity(f)] < severityRank[args.minSeverity] {
			continue
		}
		if args.fixedOnly && f.FixedVersion == "" {
			continue
		}
		if args.shippedOnly && f.Package.InstallScope == string(altshiftSbomTypes.ScopeExcluded) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// sortFindings orders findings by severity (worst first), then package and vulnerability.
func sortFindings(findings []*sbomScanningFinding.Finding) {
	slices.SortStableFunc(findings, func(a, b *sbomScanningFinding.Finding) int {
		return cmp.Or(
			cmp.Compare(severityRank[findingSeverity(b)], severityRank[findingSeverity(a)]),
			cmp.Compare(a.Package.Name, b.Package.Name),
			cmp.Compare(a.Package.Version, b.Package.Version),
			cmp.Compare(a.Vulnerability.Id, b.Vulnerability.Id),
		)
	})
}

func writeJson(writer io.Writer, r *report) error {
	if r.Findings == nil {
		r.Findings = []*sbomScanningFinding.Finding{}
	}
	data, err := json.Marshal(r)
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), r.Source)
	}
	if _, err := writer.Write(append(data, '\n')); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("write: %w", err))
	}
	return nil
}

// writeTable prints the findings as a table followed by a count per severity.
func writeTable(writer io.Writer, findings []*sbomScanningFinding.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(writer, "no vulnerabilities found")
		return
	}

	table := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "SEVERITY\tVULNERABILITY\tPACKAGE\tVERSION\tFIXED\tSCOPE\tIMAGE")
	counts := make(map[string]int)
	for _, f := range findings {
		severity := findingSeverity(f)
		counts[severity]++
		var image string
		if f.Container != nil && f.Container.Image != nil {
			image = f.Container.Image.Name
			if f.Container.Image.Tag != "" {
				image += ":" + f.Container.Image.Tag
			}
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", severity, f.Vulnerability.Id, f.Package.Name, f.Package.Version, cmp.Or(f.FixedVersion, "-"), cmp.Or(f.Package.InstallScope, "-"), cmp.Or(image, "-"))
	}
	_ = table.Flush()

	var parts []string
	for _, severity := range []string{dbTypes.SeverityCritical.String(), dbTypes.SeverityHigh.String(), dbTypes.SeverityMedium.String(), dbTypes.SeverityLow.String(), dbTypes.SeverityUnknown.String()} {
		if counts[severity] != 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[severity], strings.ToLower(severity)))
		}
	}
	fmt.Fprintf(writer, "\n%d finding(s): %s\n", len(findings), strings.Join(parts, ", "))
}

func main() {
	// trivy-db turns the process-wide default logger up to debug when imported; the libraries used here then log
	// every fetch. Only warnings and worse belong on a user's terminal.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	registry, err := url.Parse(trivyDatabaseRegistry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbom_scanning: error: %v\n", err)
		os.Exit(exitError)
	}

	stdinInfo, statErr := os.Stdin.Stat()
	stdinIsTerminal := statErr == nil && stdinInfo.Mode()&os.ModeCharDevice != 0

	code, err := run(ctx, os.Args[1:], os.Stdin, stdinIsTerminal, os.Stdout, os.Stderr, registry, time.Now)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbom_scanning: error: %v\n", err)
	}
	os.Exit(code)
}
