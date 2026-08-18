package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sbomScanningFinding "github.com/altshiftab/sbom_scanning/pkg/types/finding"
	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "go.etcd.io/bbolt"
)

// newTestDatabase writes a small Trivy database into a directory: lodash < 4.17.21 vulnerable, one unfixed advisory,
// and busybox on alpine 3.18. The trivy-db connection is a process-wide singleton, so it is closed again afterwards.
func newTestDatabase(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := db.Init(dir); err != nil {
		t.Fatalf("db init: %v", err)
	}
	dbc := db.Config{}
	err := dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte("vulnerability")); err != nil {
			return err
		}
		npmBucket := "npm::GitHub Security Advisory npm"
		if err := dbc.PutDataSource(tx, npmBucket, dbTypes.DataSource{ID: vulnerability.GHSA, Name: "GitHub Security Advisory npm"}); err != nil {
			return err
		}
		if err := dbc.PutAdvisory(tx, []string{npmBucket, "lodash"}, "CVE-2021-23337", &dbTypes.Advisory{VulnerableVersions: []string{"<4.17.21"}, PatchedVersions: []string{"4.17.21"}}); err != nil {
			return err
		}
		if err := dbc.PutAdvisory(tx, []string{npmBucket, "lodash"}, "GHSA-unfixed", &dbTypes.Advisory{VulnerableVersions: []string{"<=4.17.20"}}); err != nil {
			return err
		}
		if err := dbc.PutVulnerability(tx, "CVE-2021-23337", dbTypes.Vulnerability{Title: "command injection", VendorSeverity: dbTypes.VendorSeverity{vulnerability.NVD: dbTypes.SeverityHigh}}); err != nil {
			return err
		}
		if err := dbc.PutVulnerability(tx, "GHSA-unfixed", dbTypes.Vulnerability{VendorSeverity: dbTypes.VendorSeverity{vulnerability.GHSA: dbTypes.SeverityLow}}); err != nil {
			return err
		}
		if err := dbc.PutDataSource(tx, "alpine 3.18", dbTypes.DataSource{ID: vulnerability.Alpine, Name: "Alpine Secdb"}); err != nil {
			return err
		}
		if err := dbc.PutAdvisory(tx, []string{"alpine 3.18", "busybox"}, "CVE-2023-42366", &dbTypes.Advisory{FixedVersion: "1.36.1-r17"}); err != nil {
			return err
		}
		return dbc.PutVulnerability(tx, "CVE-2023-42366", dbTypes.Vulnerability{VendorSeverity: dbTypes.VendorSeverity{vulnerability.NVD: dbTypes.SeverityMedium}})
	})
	if err != nil {
		t.Fatalf("fill db: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db close: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, metadataFileName), []byte(`{"Version":2,"UpdatedAt":"2026-08-18T12:00:00Z","NextUpdate":"2026-08-19T12:00:00Z"}`), 0o600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	return dir
}

const lodashSbom = `{"bomFormat": "CycloneDX", "specVersion": "1.6",
	"metadata": {"component": {"type": "container", "name": "localhost/app", "version": "latest", "purl": "pkg:docker/localhost/app@latest", "properties": [{"name": "altshift:sbom:image", "value": "localhost/app:latest"}]}},
	"components": [
		{"type": "library", "name": "lodash", "version": "4.17.20", "scope": "required", "purl": "pkg:npm/lodash@4.17.20"},
		{"type": "container", "name": "golang", "version": "1.26-alpine", "scope": "excluded", "purl": "pkg:docker/golang@1.26-alpine",
			"properties": [{"name": "altshift:sbom:image", "value": "docker.io/library/golang:1.26-alpine"}],
			"components": [{"type": "library", "name": "busybox", "version": "1.36.1-r15", "scope": "excluded", "purl": "pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64&distro=alpine-3.18.4"}]}
	]}`

func TestMain(m *testing.M) {
	// As main does: keep the libraries' debug logging (trivy-db enables it process-wide) out of the test output.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	os.Exit(m.Run())
}

func runCommand(t *testing.T, stdin string, stdinIsTerminal bool, registry *url.URL, args ...string) (int, string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	now := func() time.Time { return time.Date(2026, 8, 18, 13, 0, 0, 0, time.UTC) }
	code, err := run(context.Background(), args, strings.NewReader(stdin), stdinIsTerminal, &stdout, &stderr, registry, now)
	return code, stdout.String(), stderr.String(), err
}

func TestRunUsage(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		args         []string
		stdin        string
		expectedCode int
		stderr       string
	}{
		{name: "help", args: []string{"--help"}, expectedCode: exitClean},
		{name: "unknown option", args: []string{"--nope"}, expectedCode: exitUsage, stderr: "error"},
		{name: "nothing to scan on a terminal", args: nil, expectedCode: exitUsage, stderr: "nothing to scan"},
		{name: "empty piped input is nothing to scan", args: nil, stdin: "  \n", expectedCode: exitUsage, stderr: "nothing to scan"},
		{name: "bad format choice", args: []string{"--format", "yaml", "x.json"}, expectedCode: exitUsage, stderr: "error"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			code, _, stderr, err := runCommand(t, testCase.stdin, testCase.stdin == "", nil, testCase.args...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != testCase.expectedCode || !strings.Contains(stderr, testCase.stderr) {
				t.Errorf("expected exit %d with %q, got %d %q", testCase.expectedCode, testCase.stderr, code, stderr)
			}
		})
	}
}

//nolint:paralleltest // The trivy-db connection is a process-wide singleton, so database-backed tests run one at a time.
func TestRunScans(t *testing.T) {
	database := newTestDatabase(t)
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(lodashSbom), 0o600); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	testCases := []struct {
		name         string
		stdin        string
		terminal     bool
		args         []string
		expectedCode int
		stdout       []string
		absent       []string
	}{
		{
			name:         "file, table",
			terminal:     true,
			args:         []string{"--database", database, sbomPath},
			expectedCode: exitClean,
			stdout:       []string{"HIGH", "CVE-2021-23337", "lodash", "4.17.21", "required", "localhost/app:latest", "MEDIUM", "CVE-2023-42366", "busybox", "excluded", "docker.io/library/golang:1.26-alpine", "LOW", "GHSA-unfixed", "3 finding(s): 1 high, 1 medium, 1 low"},
		},
		{
			name:         "piped stdin without a name",
			stdin:        lodashSbom,
			args:         []string{"--database", database},
			expectedCode: exitClean,
			stdout:       []string{"CVE-2021-23337"},
			absent:       []string{"\n-\n"},
		},
		{
			name:         "min severity and fail-on",
			terminal:     true,
			args:         []string{"--database", database, "--min-severity", "MEDIUM", "--fail-on", "HIGH", sbomPath},
			expectedCode: exitFindings,
			stdout:       []string{"CVE-2021-23337", "CVE-2023-42366", "2 finding(s)"},
			absent:       []string{"GHSA-unfixed"},
		},
		{
			name:         "shipped only and fixed only",
			terminal:     true,
			args:         []string{"--database", database, "--shipped-only", "--fixed-only", sbomPath},
			expectedCode: exitClean,
			stdout:       []string{"CVE-2021-23337", "1 finding(s)"},
			absent:       []string{"CVE-2023-42366", "GHSA-unfixed"},
		},
		{
			name:         "fail-on not reached",
			terminal:     true,
			args:         []string{"--database", database, "--fail-on", "CRITICAL", sbomPath},
			expectedCode: exitClean,
		},
		{
			name:         "json",
			terminal:     true,
			args:         []string{"--database", database, "--format", "json", sbomPath},
			expectedCode: exitClean,
			stdout:       []string{`"source":"` + sbomPath + `"`, `"CVE-2021-23337"`},
		},
		{
			name:         "two files get headings",
			terminal:     true,
			args:         []string{"--database", database, sbomPath, sbomPath},
			expectedCode: exitClean,
			stdout:       []string{sbomPath + "\n", "\n" + sbomPath + "\n"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) { //nolint:paralleltest // shares the database connection
			code, stdout, stderr, err := runCommand(t, testCase.stdin, testCase.terminal, nil, testCase.args...)
			if err != nil {
				t.Fatalf("unexpected error: %v (%s)", err, stderr)
			}
			if code != testCase.expectedCode {
				t.Errorf("expected exit %d, got %d (%s)", testCase.expectedCode, code, stderr)
			}
			for _, expected := range testCase.stdout {
				if !strings.Contains(stdout, expected) {
					t.Errorf("expected stdout to contain %q, got:\n%s", expected, stdout)
				}
			}
			for _, absent := range testCase.absent {
				if strings.Contains(stdout, absent) {
					t.Errorf("expected stdout not to contain %q, got:\n%s", absent, stdout)
				}
			}
			if strings.Contains(stderr, "days old") {
				t.Errorf("did not expect a staleness warning for a fresh database, got %q", stderr)
			}
		})
	}
}

//nolint:paralleltest // The trivy-db connection is a process-wide singleton, so database-backed tests run one at a time.
func TestRunJsonReport(t *testing.T) {
	database := newTestDatabase(t)

	code, stdout, _, err := runCommand(t, lodashSbom, false, nil, "--database", database, "--format", "json")
	if err != nil || code != exitClean {
		t.Fatalf("unexpected result: %d %v", code, err)
	}
	var r struct {
		Source   string                         `json:"source"`
		Findings []*sbomScanningFinding.Finding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("stdout is not a report: %v: %s", err, stdout)
	}
	if r.Source != stdinName || len(r.Findings) != 3 || r.Findings[0].Vulnerability.Id != "CVE-2021-23337" || r.Findings[0].FixedVersion != "4.17.21" {
		t.Errorf("unexpected report: %+v", r)
	}
}

//nolint:paralleltest // The trivy-db connection is a process-wide singleton, so database-backed tests run one at a time.
func TestRunImage(t *testing.T) {
	database := newTestDatabase(t)

	// The fake podman serves an image holding a node package the database knows about.
	var layer bytes.Buffer
	layerWriter := tar.NewWriter(&layer)
	content := []byte(`{"name": "lodash", "version": "4.17.20"}`)
	if err := layerWriter.WriteHeader(&tar.Header{Name: "app/node_modules/lodash/package.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := layerWriter.Write(content); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = layerWriter.Close()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	write := func(name string, data []byte) {
		_ = writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o444, Size: int64(len(data))})
		_, _ = writer.Write(data)
	}
	write("layer0.tar", layer.Bytes())
	write("cfg.json", []byte(`{"rootfs":{"diff_ids":["sha256:l0"]}}`))
	write("manifest.json", []byte(`[{"Config":"cfg.json","RepoTags":["localhost/app:latest"],"Layers":["layer0.tar"]}]`))
	_ = writer.Close()
	dir := t.TempDir()
	fixture := filepath.Join(dir, "image.tar")
	if err := os.WriteFile(fixture, archive.Bytes(), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	podman := filepath.Join(dir, "podman")
	if err := os.WriteFile(podman, []byte("#!/bin/sh\ncat '"+fixture+"'\n"), 0o700); err != nil { //nolint:gosec // executable test script
		t.Fatalf("write podman: %v", err)
	}

	code, stdout, stderr, err := runCommand(t, "", true, nil, "--database", database, "--podman", podman, "--image", "localhost/app:latest")
	if err != nil || code != exitClean {
		t.Fatalf("unexpected result: %d %v (%s)", code, err, stderr)
	}
	for _, expected := range []string{"localhost/app:latest\n", "CVE-2021-23337", "lodash", "required"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("expected stdout to contain %q, got:\n%s", expected, stdout)
		}
	}
}

// databaseArchive gzips a tarball of the database directory's files, as the registry publishes it.
func databaseArchive(t *testing.T, dir string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, name := range []string{databaseFileName, metadataFileName} {
		data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // test fixture
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	_ = tarWriter.Close()
	_ = gzipWriter.Close()
	return buffer.Bytes()
}

// newTestRegistry serves the database artifact the way ghcr.io does: an anonymous token, an OCI manifest, a blob.
func newTestRegistry(t *testing.T, archive []byte) *url.URL {
	t.Helper()
	const digest = "sha256:0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if r.URL.Query().Get("scope") != "repository:aquasecurity/trivy-db:pull" {
				http.Error(w, "bad scope", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"token": "anonymous-token"}`))
		case "/v2/aquasecurity/trivy-db/manifests/2":
			if r.Header.Get("Authorization") != "Bearer anonymous-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = w.Write([]byte(`{"schemaVersion": 2, "layers": [{"mediaType": "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip", "digest": "` + digest + `", "size": ` + itoa(len(archive)) + `}]}`))
		case "/v2/aquasecurity/trivy-db/blobs/" + digest:
			if r.Header.Get("Authorization") != "Bearer anonymous-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	registry, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return registry
}

func itoa(n int) string {
	data, _ := json.Marshal(n)
	return string(data)
}

//nolint:paralleltest // The trivy-db connection is a process-wide singleton, so database-backed tests run one at a time.
func TestRunDownloadsMissingDatabase(t *testing.T) {
	source := newTestDatabase(t)
	registry := newTestRegistry(t, databaseArchive(t, source))
	target := filepath.Join(t.TempDir(), "db")

	code, stdout, stderr, err := runCommand(t, lodashSbom, false, registry, "--database", target)
	if err != nil || code != exitClean {
		t.Fatalf("unexpected result: %d %v (%s)", code, err, stderr)
	}
	if !strings.Contains(stderr, "no database in") || !strings.Contains(stderr, "downloading the vulnerability database") {
		t.Errorf("expected download notes on stderr, got %q", stderr)
	}
	if !strings.Contains(stdout, "CVE-2021-23337") {
		t.Errorf("expected findings from the downloaded database, got:\n%s", stdout)
	}
	for _, name := range []string{databaseFileName, metadataFileName} {
		if _, err := os.Stat(filepath.Join(target, name)); err != nil {
			t.Errorf("expected %s in the target: %v", name, err)
		}
	}
	// No temp files left behind.
	entries, _ := os.ReadDir(target)
	if len(entries) != 2 {
		t.Errorf("expected exactly the two database files, got %v", entries)
	}
}

//nolint:paralleltest // The trivy-db connection is a process-wide singleton, so database-backed tests run one at a time.
func TestRunUpdateAndStaleness(t *testing.T) {
	database := newTestDatabase(t)

	// A stale database is pointed out.
	if err := os.WriteFile(filepath.Join(database, metadataFileName), []byte(`{"Version":2,"UpdatedAt":"2026-08-01T12:00:00Z"}`), 0o600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	code, _, stderr, err := runCommand(t, lodashSbom, false, nil, "--database", database)
	if err != nil || code != exitClean || !strings.Contains(stderr, "17 days old") {
		t.Errorf("expected a staleness warning, got %d %v %q", code, err, stderr)
	}

	// --update replaces it with what the registry has, and needs nothing to scan.
	fresh := newTestDatabase(t)
	registry := newTestRegistry(t, databaseArchive(t, fresh))
	code, stdout, stderr, err := runCommand(t, "", true, registry, "--database", database, "--update")
	if err != nil || code != exitClean || !strings.Contains(stderr, "downloading") || strings.Contains(stderr, "days old") || stdout != "" {
		t.Errorf("expected an update on its own, got %d %v stdout %q stderr %q", code, err, stdout, stderr)
	}
	if databaseAge(database, time.Date(2026, 8, 18, 13, 0, 0, 0, time.UTC)) != time.Hour {
		t.Errorf("expected the fresh metadata after the update")
	}

	// And with something to scan, it updates first and scans with the result.
	registry = newTestRegistry(t, databaseArchive(t, fresh))
	code, stdout, stderr, err = runCommand(t, lodashSbom, false, registry, "--database", database, "--update")
	if err != nil || code != exitClean || !strings.Contains(stderr, "downloading") || !strings.Contains(stdout, "CVE-2021-23337") {
		t.Errorf("expected an update followed by a scan, got %d %v stdout %q stderr %q", code, err, stdout, stderr)
	}
}

func TestFilterAndSortFindings(t *testing.T) {
	t.Parallel()

	finding := func(id, severity, pkg, fixed, scope string) *sbomScanningFinding.Finding {
		return &sbomScanningFinding.Finding{
			Vulnerability: &schema.Vulnerability{Id: id, Severity: severity},
			Package:       &schema.Package{Name: pkg, Version: "1", InstallScope: scope},
			FixedVersion:  fixed,
		}
	}
	findings := []*sbomScanningFinding.Finding{
		finding("CVE-3", "LOW", "b", "", "required"),
		finding("CVE-1", "HIGH", "b", "2", "excluded"),
		finding("CVE-2", "HIGH", "a", "2", "required"),
		finding("CVE-4", "", "c", "3", ""),
		nil,
	}

	testCases := []struct {
		name     string
		args     *arguments
		expected []string
	}{
		{name: "all, sorted", args: &arguments{minSeverity: "UNKNOWN"}, expected: []string{"CVE-2", "CVE-1", "CVE-3", "CVE-4"}},
		{name: "min severity", args: &arguments{minSeverity: "HIGH"}, expected: []string{"CVE-2", "CVE-1"}},
		{name: "fixed only", args: &arguments{minSeverity: "UNKNOWN", fixedOnly: true}, expected: []string{"CVE-2", "CVE-1", "CVE-4"}},
		{name: "shipped only", args: &arguments{minSeverity: "UNKNOWN", shippedOnly: true}, expected: []string{"CVE-2", "CVE-3", "CVE-4"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			kept := filterFindings(findings, testCase.args)
			sortFindings(kept)
			var ids []string
			for _, f := range kept {
				ids = append(ids, f.Vulnerability.Id)
			}
			if strings.Join(ids, ",") != strings.Join(testCase.expected, ",") {
				t.Errorf("expected %v, got %v", testCase.expected, ids)
			}
		})
	}
}

func TestWriteTableEmpty(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	writeTable(&buffer, nil)
	if buffer.String() != "no vulnerabilities found\n" {
		t.Errorf("unexpected output %q", buffer.String())
	}
}
