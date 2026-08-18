package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	sbomScanningFinding "github.com/altshiftab/sbom_scanning/pkg/types/finding"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "go.etcd.io/bbolt"
)

func TestPurlToLangEcosystem(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		purlType string
		expected ecosystem.Type
		ok       bool
	}{
		{name: "npm", purlType: "npm", expected: ecosystem.Npm, ok: true},
		{name: "pypi", purlType: "pypi", expected: ecosystem.Pip, ok: true},
		{name: "gem", purlType: "gem", expected: ecosystem.RubyGems, ok: true},
		{name: "maven", purlType: "maven", expected: ecosystem.Maven, ok: true},
		{name: "gradle", purlType: "gradle", expected: ecosystem.Maven, ok: true},
		{name: "cargo", purlType: "cargo", expected: ecosystem.Cargo, ok: true},
		{name: "golang", purlType: "golang", expected: ecosystem.Go, ok: true},
		{name: "nuget", purlType: "nuget", expected: ecosystem.NuGet, ok: true},
		{name: "composer", purlType: "composer", expected: ecosystem.Composer, ok: true},
		{name: "swift", purlType: "swift", expected: ecosystem.Swift, ok: true},
		{name: "cocoapods", purlType: "cocoapods", expected: ecosystem.Cocoapods, ok: true},
		{name: "pub", purlType: "pub", expected: ecosystem.Pub, ok: true},
		{name: "hex", purlType: "hex", expected: ecosystem.Erlang, ok: true},
		{name: "conan", purlType: "conan", expected: ecosystem.Conan, ok: true},
		{name: "bitnami", purlType: "bitnami", expected: ecosystem.Bitnami, ok: true},
		{name: "julia", purlType: "julia", expected: ecosystem.Julia, ok: true},
		{name: "os package type", purlType: "deb", ok: false},
		{name: "unknown", purlType: "generic", ok: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			eco, match, ok := purlToLangEcosystem(testCase.purlType)
			if ok != testCase.ok {
				t.Fatalf("expected ok=%t, got %t", testCase.ok, ok)
			}
			if !ok {
				return
			}
			if eco != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, eco)
			}
			if match == nil {
				t.Errorf("expected a version matcher")
			}
		})
	}
}

func TestCreateFixedVersions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		advisory dbTypes.Advisory
		expected string
	}{
		{name: "patched versions", advisory: dbTypes.Advisory{PatchedVersions: []string{"1.2.3", "2.0.1", "1.2.3"}}, expected: "1.2.3, 2.0.1"},
		{name: "upper bounds of vulnerable ranges", advisory: dbTypes.Advisory{VulnerableVersions: []string{">=1.0.0, <1.2.3", "<2.0.1"}}, expected: "1.2.3, 2.0.1"},
		{name: "inclusive upper bound is not a fix", advisory: dbTypes.Advisory{VulnerableVersions: []string{"<=1.2.3"}}, expected: ""},
		{name: "spaces", advisory: dbTypes.Advisory{VulnerableVersions: []string{"< 1.2.3"}}, expected: "1.2.3"},
		{name: "nothing", advisory: dbTypes.Advisory{}, expected: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := createFixedVersions(testCase.advisory); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}

func TestAutoDetectSeverity(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		vulnId         string
		vuln           dbTypes.Vulnerability
		dataSourceId   dbTypes.SourceID
		expected       string
		expectedSource dbTypes.SourceID
	}{
		{
			name:           "data source severity",
			vulnId:         "CVE-2024-0001",
			vuln:           dbTypes.Vulnerability{VendorSeverity: dbTypes.VendorSeverity{vulnerability.Debian: dbTypes.SeverityLow, vulnerability.NVD: dbTypes.SeverityHigh}},
			dataSourceId:   vulnerability.Debian,
			expected:       "LOW",
			expectedSource: vulnerability.Debian,
		},
		{
			name:           "nvd fallback",
			vulnId:         "CVE-2024-0001",
			vuln:           dbTypes.Vulnerability{VendorSeverity: dbTypes.VendorSeverity{vulnerability.NVD: dbTypes.SeverityHigh, vulnerability.GHSA: dbTypes.SeverityCritical}},
			dataSourceId:   vulnerability.Debian,
			expected:       "HIGH",
			expectedSource: vulnerability.NVD,
		},
		{
			name:           "ghsa id prefers github",
			vulnId:         "GHSA-xxxx-yyyy-zzzz",
			vuln:           dbTypes.Vulnerability{VendorSeverity: dbTypes.VendorSeverity{vulnerability.NVD: dbTypes.SeverityHigh, vulnerability.GHSA: dbTypes.SeverityCritical}},
			dataSourceId:   vulnerability.RubySec,
			expected:       "CRITICAL",
			expectedSource: vulnerability.GHSA,
		},
		{
			name:         "precomputed severity",
			vulnId:       "CVE-2024-0001",
			vuln:         dbTypes.Vulnerability{Severity: "MEDIUM"},
			dataSourceId: vulnerability.NVD,
			expected:     "MEDIUM",
		},
		{
			name:     "unknown",
			vulnId:   "CVE-2024-0001",
			vuln:     dbTypes.Vulnerability{},
			expected: "UNKNOWN",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			severity, source := autoDetectSeverity(testCase.vulnId, &testCase.vuln, testCase.dataSourceId)
			if severity != testCase.expected || source != testCase.expectedSource {
				t.Errorf("expected (%q, %q), got (%q, %q)", testCase.expected, testCase.expectedSource, severity, source)
			}
		})
	}
}

func TestGetPrimaryUrl(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		vulnId   string
		refs     []string
		source   dbTypes.SourceID
		expected string
	}{
		{name: "cve", vulnId: "CVE-2024-0001", expected: "https://avd.aquasec.com/nvd/cve-2024-0001"},
		{name: "rustsec", vulnId: "RUSTSEC-2024-0001", expected: "https://osv.dev/vulnerability/RUSTSEC-2024-0001"},
		{name: "ghsa", vulnId: "GHSA-xxxx-yyyy-zzzz", expected: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"},
		{name: "temp", vulnId: "TEMP-0000001-ABCDEF", expected: "https://security-tracker.debian.org/tracker/TEMP-0000001-ABCDEF"},
		{name: "debian reference", vulnId: "DSA-5000-1", refs: []string{"https://example.com", "https://www.debian.org/security/2021/dsa-5000"}, source: vulnerability.Debian, expected: "https://www.debian.org/security/2021/dsa-5000"},
		{name: "ubuntu reference", vulnId: "USN-5000-1", refs: []string{"https://usn.ubuntu.com/5000-1/"}, source: vulnerability.Ubuntu, expected: "https://usn.ubuntu.com/5000-1/"},
		{name: "red hat reference", vulnId: "RHSA-2024:0001", refs: []string{"https://access.redhat.com/errata/RHSA-2024:0001"}, source: vulnerability.RedHat, expected: "https://access.redhat.com/errata/RHSA-2024:0001"},
		{name: "no matching reference", vulnId: "RHSA-2024:0001", refs: []string{"https://example.com"}, source: vulnerability.RedHat, expected: ""},
		{name: "unknown source", vulnId: "XYZ-1", refs: []string{"https://www.debian.org/x"}, source: "other", expected: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := getPrimaryUrl(testCase.vulnId, testCase.refs, testCase.source); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}

func TestDetectEnumeration(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		vulnId   string
		expected string
	}{
		{name: "cve", vulnId: "CVE-2024-0001", expected: "CVE"},
		{name: "ghsa", vulnId: "GHSA-xxxx-yyyy-zzzz", expected: "GHSA"},
		{name: "no dash", vulnId: "XYZ", expected: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := detectEnumeration(testCase.vulnId); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}

func TestCvssScore(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		cvss     dbTypes.CVSS
		expected *schema.VulnerabilityScore
	}{
		{name: "v4 wins", cvss: dbTypes.CVSS{V40Score: 9.3, V40Vector: "CVSS:4.0/AV:N", V3Score: 9.8, V3Vector: "CVSS:3.1/AV:N", V2Score: 7.5}, expected: &schema.VulnerabilityScore{Base: 9.3, Version: "4.0"}},
		{name: "v3.1 from vector", cvss: dbTypes.CVSS{V3Score: 9.8, V3Vector: "CVSS:3.1/AV:N/AC:L", V2Score: 7.5}, expected: &schema.VulnerabilityScore{Base: 9.8, Version: "3.1"}},
		{name: "v3.0 from vector", cvss: dbTypes.CVSS{V3Score: 9.8, V3Vector: "CVSS:3.0/AV:N/AC:L"}, expected: &schema.VulnerabilityScore{Base: 9.8, Version: "3.0"}},
		{name: "v3 without vector", cvss: dbTypes.CVSS{V3Score: 5.0}, expected: &schema.VulnerabilityScore{Base: 5.0, Version: "3.1"}},
		{name: "v2 only", cvss: dbTypes.CVSS{V2Score: 7.5, V2Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"}, expected: &schema.VulnerabilityScore{Base: 7.5, Version: "2.0"}},
		{name: "no score", cvss: dbTypes.CVSS{V3Vector: "CVSS:3.1/AV:N"}, expected: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := cvssScore(testCase.cvss)
			if testCase.expected == nil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil || *got != *testCase.expected {
				t.Errorf("expected %+v, got %+v", testCase.expected, got)
			}
		})
	}
}

// newTestScanner builds a Trivy database in a temporary directory with fill and opens a Scanner on it. The database
// connection is a package-level singleton in trivy-db, so tests using it cannot run in parallel.
func newTestScanner(t *testing.T, fill func(tx *bolt.Tx, dbc db.Config) error) *Scanner {
	t.Helper()

	dbDir := t.TempDir()
	if err := db.Init(dbDir); err != nil {
		t.Fatalf("db init: %v", err)
	}
	dbc := db.Config{}
	err := dbc.BatchUpdate(func(tx *bolt.Tx) error {
		// The vulnerability bucket always exists in a real database; trivy-db assumes so when reading it.
		if _, err := tx.CreateBucketIfNotExists([]byte("vulnerability")); err != nil {
			return err
		}
		return fill(tx, dbc)
	})
	if err != nil {
		t.Fatalf("fill db: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db close: %v", err)
	}

	scanner, err := New(dbDir)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}
	t.Cleanup(func() {
		if err := scanner.Close(); err != nil {
			t.Errorf("scanner close: %v", err)
		}
	})
	return scanner
}

func putAdvisory(t *testing.T, tx *bolt.Tx, dbc db.Config, bucketName, pkgName, vulnId string, advisory any) {
	t.Helper()
	if err := dbc.PutAdvisory(tx, []string{bucketName, pkgName}, vulnId, advisory); err != nil {
		t.Fatalf("put advisory %s/%s/%s: %v", bucketName, pkgName, vulnId, err)
	}
}

func putDataSource(t *testing.T, tx *bolt.Tx, dbc db.Config, bucketName string, source dbTypes.DataSource) {
	t.Helper()
	if err := dbc.PutDataSource(tx, bucketName, source); err != nil {
		t.Fatalf("put data source %s: %v", bucketName, err)
	}
}

func putVulnerability(t *testing.T, tx *bolt.Tx, dbc db.Config, vulnId string, vuln dbTypes.Vulnerability) {
	t.Helper()
	if err := dbc.PutVulnerability(tx, vulnId, vuln); err != nil {
		t.Fatalf("put vulnerability %s: %v", vulnId, err)
	}
}

var (
	testPublished = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

	npmSource     = dbTypes.DataSource{ID: vulnerability.GHSA, Name: "GitHub Security Advisory npm", URL: "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"}
	pipSource     = dbTypes.DataSource{ID: vulnerability.GHSA, Name: "GitHub Security Advisory pip", URL: "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip"}
	mavenSource   = dbTypes.DataSource{ID: vulnerability.GHSA, Name: "GitHub Security Advisory Maven", URL: "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven"}
	debianSource  = dbTypes.DataSource{ID: vulnerability.Debian, Name: "Debian Security Tracker", URL: "https://salsa.debian.org/security-tracker-team/security-tracker"}
	ubuntuSource  = dbTypes.DataSource{ID: vulnerability.Ubuntu, Name: "Ubuntu CVE Tracker", URL: "https://git.launchpad.net/ubuntu-cve-tracker"}
	alpineSource  = dbTypes.DataSource{ID: vulnerability.Alpine, Name: "Alpine Secdb", URL: "https://secdb.alpinelinux.org/"}
	redHatSource  = dbTypes.DataSource{ID: vulnerability.RedHatOVAL, Name: "Red Hat OVAL v2", URL: "https://www.redhat.com/security/data/oval/v2/"}
	rockySource   = dbTypes.DataSource{ID: vulnerability.Rocky, Name: "Rocky Linux updateinfo", URL: "https://download.rockylinux.org/pub/rocky/"}
	oracleSource  = dbTypes.DataSource{ID: vulnerability.OracleOVAL, Name: "Oracle Linux OVAL definitions", URL: "https://linux.oracle.com/security/oval/"}
	amazonSource  = dbTypes.DataSource{ID: vulnerability.Amazon, Name: "Amazon Linux Security Center", URL: "https://alas.aws.amazon.com/"}
	photonSource  = dbTypes.DataSource{ID: vulnerability.Photon, Name: "Photon OS CVE metadata", URL: "https://packages.vmware.com/photon/photon_cve_metadata/"}
	rootIoSource  = dbTypes.DataSource{ID: vulnerability.RootIO, BaseID: vulnerability.Debian, Name: "Root.io Security Patches (debian)", URL: "https://api.root.io/external/patch_feed"}
	suseSource    = dbTypes.DataSource{ID: vulnerability.SuseCVRF, Name: "SUSE CVRF", URL: "https://ftp.suse.com/pub/projects/security/cvrf/"}
	wolfiSource   = dbTypes.DataSource{ID: vulnerability.Wolfi, Name: "Wolfi Secdb", URL: "https://packages.wolfi.dev/os/security.json"}
	almaSource    = dbTypes.DataSource{ID: vulnerability.Alma, Name: "AlmaLinux Product Errata", URL: "https://errata.almalinux.org/"}
	genericSource = dbTypes.DataSource{ID: vulnerability.GHSA, Name: "GitHub Security Advisory Go", URL: "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago"}
)

// fillTestDb writes the fixture the end-to-end scan tests run against.
func fillTestDb(t *testing.T) func(tx *bolt.Tx, dbc db.Config) error {
	return func(tx *bolt.Tx, dbc db.Config) error {
		// Language ecosystems.
		npmBucket := "npm::" + npmSource.Name
		putDataSource(t, tx, dbc, npmBucket, npmSource)
		putAdvisory(t, tx, dbc, npmBucket, "lodash", "CVE-2021-23337", &dbTypes.Advisory{VulnerableVersions: []string{"<4.17.21"}, PatchedVersions: []string{"4.17.21"}})
		putAdvisory(t, tx, dbc, npmBucket, "lodash", "GHSA-old0-old0-old0", &dbTypes.Advisory{VulnerableVersions: []string{"<4.0.0"}, PatchedVersions: []string{"4.0.0"}})
		putAdvisory(t, tx, dbc, npmBucket, "@babel/traverse", "GHSA-67hx-6x53-jw92", &dbTypes.Advisory{VulnerableVersions: []string{"<7.23.2"}, PatchedVersions: []string{"7.23.2"}})
		putVulnerability(t, tx, dbc, "CVE-2021-23337", dbTypes.Vulnerability{
			Title:          "nodejs-lodash: command injection via template",
			Description:    "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
			Severity:       "HIGH",
			CweIDs:         []string{"CWE-77"},
			VendorSeverity: dbTypes.VendorSeverity{vulnerability.NVD: dbTypes.SeverityHigh, vulnerability.GHSA: dbTypes.SeverityHigh, vulnerability.RedHat: dbTypes.SeverityMedium},
			CVSS: dbTypes.VendorCVSS{
				vulnerability.NVD:    {V2Vector: "AV:N/AC:L/Au:S/C:P/I:P/A:P", V2Score: 6.5, V3Vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", V3Score: 7.2},
				vulnerability.RedHat: {V3Vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", V3Score: 7.2},
			},
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-23337", "https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c"},
			PublishedDate:    &testPublished,
			LastModifiedDate: &testPublished,
		})
		putVulnerability(t, tx, dbc, "GHSA-67hx-6x53-jw92", dbTypes.Vulnerability{
			Title:          "Babel vulnerable to arbitrary code execution when compiling specifically crafted malicious code",
			VendorSeverity: dbTypes.VendorSeverity{vulnerability.GHSA: dbTypes.SeverityCritical, vulnerability.NVD: dbTypes.SeverityHigh},
			CVSS:           dbTypes.VendorCVSS{vulnerability.GHSA: {V3Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", V3Score: 9.4}},
		})

		pipBucket := "pip::" + pipSource.Name
		putDataSource(t, tx, dbc, pipBucket, pipSource)
		putAdvisory(t, tx, dbc, pipBucket, "django", "CVE-2023-31047", &dbTypes.Advisory{VulnerableVersions: []string{">=4.2, <4.2.1", ">=4.1, <4.1.9", ">=3.2, <3.2.19"}, PatchedVersions: []string{"4.2.1", "4.1.9", "3.2.19"}})

		mavenBucket := "maven::" + mavenSource.Name
		putDataSource(t, tx, dbc, mavenBucket, mavenSource)
		putAdvisory(t, tx, dbc, mavenBucket, "org.apache.logging.log4j:log4j-core", "CVE-2021-44228", &dbTypes.Advisory{VulnerableVersions: []string{">=2.13.0, <2.15.0", ">=2.0-beta9, <2.3.1"}, PatchedVersions: []string{"2.15.0", "2.3.1"}})

		goBucket := "go::" + genericSource.Name
		putDataSource(t, tx, dbc, goBucket, genericSource)
		putAdvisory(t, tx, dbc, goBucket, "golang.org/x/net", "CVE-2023-39325", &dbTypes.Advisory{VulnerableVersions: []string{"<0.17.0"}, PatchedVersions: []string{"0.17.0"}})

		// Debian: advisories are keyed by source package; unfixed ones carry a status and a package-specific severity.
		putDataSource(t, tx, dbc, "debian 12", debianSource)
		putAdvisory(t, tx, dbc, "debian 12", "openssl", "CVE-2023-5678", &dbTypes.Advisory{FixedVersion: "3.0.11-1~deb12u2"})
		putAdvisory(t, tx, dbc, "debian 12", "openssl", "CVE-2023-9999", &dbTypes.Advisory{Status: dbTypes.StatusAffected, Severity: dbTypes.SeverityLow})
		putAdvisory(t, tx, dbc, "debian 12", "openssl", "CVE-2023-0000", &dbTypes.Advisory{FixedVersion: "3.0.9-1"})
		putAdvisory(t, tx, dbc, "debian 11", "openssl", "CVE-2023-5678", &dbTypes.Advisory{FixedVersion: "1.1.1w-0+deb11u1"})
		putVulnerability(t, tx, dbc, "CVE-2023-5678", dbTypes.Vulnerability{
			Title:          "openssl: Generating excessively long X9.42 DH keys or checking excessively long X9.42 DH keys or parameters may be very slow",
			VendorSeverity: dbTypes.VendorSeverity{vulnerability.NVD: dbTypes.SeverityMedium, vulnerability.Debian: dbTypes.SeverityLow, vulnerability.RedHat: dbTypes.SeverityLow, vulnerability.Ubuntu: dbTypes.SeverityLow},
			CVSS:           dbTypes.VendorCVSS{vulnerability.NVD: {V3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", V3Score: 5.3}},
			References:     []string{"https://www.openssl.org/news/secadv/20231106.txt", "https://access.redhat.com/security/cve/CVE-2023-5678", "https://www.debian.org/security/2023/dsa-1"},
		})
		putVulnerability(t, tx, dbc, "CVE-2023-9999", dbTypes.Vulnerability{
			VendorSeverity: dbTypes.VendorSeverity{vulnerability.NVD: dbTypes.SeverityHigh},
		})

		// Root.io: a source that layers on Debian; severities follow the base source.
		putDataSource(t, tx, dbc, "root.io debian 12", rootIoSource)

		putDataSource(t, tx, dbc, "ubuntu 22.04", ubuntuSource)
		putAdvisory(t, tx, dbc, "ubuntu 22.04", "openssl", "CVE-2023-5678", &dbTypes.Advisory{FixedVersion: "3.0.2-0ubuntu1.13"})

		// Alpine: keyed by source package as well ("ssl_client" is built from "busybox").
		putDataSource(t, tx, dbc, "alpine 3.18", alpineSource)
		putAdvisory(t, tx, dbc, "alpine 3.18", "busybox", "CVE-2023-42363", &dbTypes.Advisory{FixedVersion: "1.36.1-r16"})
		putAdvisory(t, tx, dbc, "alpine 3.18", "busybox", "CVE-2023-42366", &dbTypes.Advisory{FixedVersion: "1.36.1-r17"})

		putDataSource(t, tx, dbc, "wolfi", wolfiSource)
		putAdvisory(t, tx, dbc, "wolfi", "glibc", "CVE-2024-2961", &dbTypes.Advisory{FixedVersion: "2.39-r5"})
		putAdvisory(t, tx, dbc, "wolfi", "glibc", "CVE-2024-9999", &dbTypes.Advisory{})

		// Red Hat: advisories are keyed by the CPEs the release's repositories map to; RHSA entries name their CVEs.
		if err := dbc.PutRedHatRepositories(tx, "rhel-9-for-x86_64-baseos-rpms", []int{1}); err != nil {
			return err
		}
		if err := dbc.PutRedHatRepositories(tx, "rhel-9-for-x86_64-appstream-rpms", []int{2}); err != nil {
			return err
		}
		if err := dbc.PutRedHatRepositories(tx, "rhel-8-for-x86_64-baseos-rpms", []int{3}); err != nil {
			return err
		}
		if err := dbc.PutRedHatNVRs(tx, "ubi9-container-9.3-1361-x86_64", []int{4}); err != nil {
			return err
		}
		putDataSource(t, tx, dbc, "Red Hat", redHatSource)
		// The Red Hat advisories are written as trivy-db stores them (redhat-oval.Advisory): CPEs as indices under
		// "Affected", severity and status as integers.
		putAdvisory(t, tx, dbc, "Red Hat", "openssl-libs", "RHSA-2024:0001", json.RawMessage(`{"Entries": [
			{"FixedVersion": "1:3.0.7-25.el9_3", "Cves": [{"ID": "CVE-2024-0001", "Severity": 3}], "Arches": ["x86_64", "aarch64"], "Status": 3, "Affected": [1]},
			{"FixedVersion": "1:3.0.7-24.el9_2", "Cves": [{"ID": "CVE-2024-0001", "Severity": 3}], "Arches": ["x86_64"], "Status": 3, "Affected": [1]},
			{"FixedVersion": "1:1.1.1k-12.el8_9", "Cves": [{"ID": "CVE-2024-0001", "Severity": 3}], "Arches": ["x86_64"], "Status": 3, "Affected": [3]}
		]}`))
		putAdvisory(t, tx, dbc, "Red Hat", "openssl-libs", "RHSA-2024:0002", json.RawMessage(`{"Entries": [
			{"FixedVersion": "1:3.0.7-30.el9_4", "Cves": [{"ID": "CVE-2024-0003", "Severity": 2}], "Arches": ["s390x"], "Status": 3, "Affected": [1]}
		]}`))
		putAdvisory(t, tx, dbc, "Red Hat", "openssl-libs", "CVE-2024-0002", json.RawMessage(`{"Entries": [
			{"Cves": [{"ID": "CVE-2024-0002", "Severity": 1}], "Status": 5, "Affected": [1, 2]}
		]}`))
		putAdvisory(t, tx, dbc, "Red Hat", "openssl-libs", "CVE-2024-0004", json.RawMessage(`{"Entries": [
			{"Cves": [{"ID": "CVE-2024-0004", "Severity": 1}], "Status": 2, "Affected": [99]}
		]}`))
		putAdvisory(t, tx, dbc, "Red Hat", "openssl-libs", "CVE-2024-0005", json.RawMessage(`{"Entries": [
			{"FixedVersion": "1:3.0.7-27.el9", "Cves": [{"ID": "CVE-2024-0005", "Severity": 2}], "Arches": ["x86_64"], "Status": 3, "Affected": [4]}
		]}`))
		putVulnerability(t, tx, dbc, "CVE-2024-0001", dbTypes.Vulnerability{
			VendorSeverity: dbTypes.VendorSeverity{vulnerability.NVD: dbTypes.SeverityCritical, vulnerability.RedHat: dbTypes.SeverityHigh},
			References:     []string{"https://access.redhat.com/errata/RHSA-2024:0001"},
		})

		// Rocky and Oracle: advisories are stored per architecture.
		putDataSource(t, tx, dbc, "rocky 9", rockySource)
		putAdvisory(t, tx, dbc, "rocky 9", "bash", "CVE-2024-1000", &dbTypes.Advisories{Entries: []dbTypes.Advisory{
			{FixedVersion: "5.1.8-9.el9", Arches: []string{"x86_64"}},
			{FixedVersion: "5.1.8-10.el9", Arches: []string{"aarch64"}},
		}})
		putAdvisory(t, tx, dbc, "rocky 9", "bash", "CVE-2024-1001", &dbTypes.Advisories{Entries: []dbTypes.Advisory{
			{FixedVersion: "5.1.8-9.el9", Arches: []string{"aarch64"}},
		}})
		putAdvisory(t, tx, dbc, "rocky 9", "bash", "CVE-2024-1002", &dbTypes.Advisories{FixedVersion: "5.1.8-7.el9"})

		putDataSource(t, tx, dbc, "Oracle Linux 8", oracleSource)
		putAdvisory(t, tx, dbc, "Oracle Linux 8", "openssl", "CVE-2024-2000", &dbTypes.Advisories{Entries: []dbTypes.Advisory{
			{FixedVersion: "1:1.1.1k-12.el8_9", Arches: []string{"x86_64"}},
			{FixedVersion: "2:1.1.1k-12.ksplice1.el8_9", Arches: []string{"x86_64"}},
		}})

		putDataSource(t, tx, dbc, "alma 9", almaSource)
		putAdvisory(t, tx, dbc, "alma 9", "nodejs:18::npm", "CVE-2024-3000", &dbTypes.Advisory{FixedVersion: "1:9.6.7-1.18.18.2.1.module_el9.2.0+53+d1c9a4c9"})

		putDataSource(t, tx, dbc, "amazon linux 2023", amazonSource)
		putAdvisory(t, tx, dbc, "amazon linux 2023", "curl", "CVE-2023-38545", &dbTypes.Advisory{FixedVersion: "8.3.0-1.amzn2023.0.2"})
		putDataSource(t, tx, dbc, "amazon linux 1", amazonSource)
		putAdvisory(t, tx, dbc, "amazon linux 1", "curl", "CVE-2019-0001", &dbTypes.Advisory{FixedVersion: "7.61.1-11.91.amzn1"})

		putDataSource(t, tx, dbc, "Photon OS 4.0", photonSource)
		putAdvisory(t, tx, dbc, "Photon OS 4.0", "openssl", "CVE-2023-5678", &dbTypes.Advisory{FixedVersion: "3.0.12-1.ph4"})

		putDataSource(t, tx, dbc, "SUSE Linux Enterprise 15.5", suseSource)
		putAdvisory(t, tx, dbc, "SUSE Linux Enterprise 15.5", "openssl-3", "CVE-2023-5678", &dbTypes.Advisory{FixedVersion: "3.0.8-150500.5.24.1"})
		putDataSource(t, tx, dbc, "openSUSE Leap 15.5", suseSource)
		putAdvisory(t, tx, dbc, "openSUSE Leap 15.5", "openssl-3", "CVE-2023-5678", &dbTypes.Advisory{FixedVersion: "3.0.8-150500.5.24.1"})

		return nil
	}
}

func cycloneDx(components ...string) string {
	return fmt.Sprintf(`{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": [%s]}`, strings.Join(components, ","))
}

type expectedFinding struct {
	vulnId         string
	pkgName        string
	pkgVersion     string
	fixedVersion   string
	status         dbTypes.Status
	severity       string
	severitySource dbTypes.SourceID
	dataSourceId   dbTypes.SourceID
}

func findingKey(vulnId, pkgName, pkgVersion string) string {
	return vulnId + "|" + pkgName + "|" + pkgVersion
}

//nolint:paralleltest // The trivy-db connection is a process-wide singleton, so database-backed tests run one at a time.
func TestScannerScan(t *testing.T) {
	scanner := newTestScanner(t, fillTestDb(t))

	testCases := []struct {
		name     string
		sbom     string
		expected []expectedFinding
		err      error
	}{
		{
			name: "empty input yields nothing",
			sbom: "",
		},
		{
			name: "malformed input",
			sbom: "{",
			err:  altshiftErrors.ErrParseError,
		},
		{
			name: "npm",
			sbom: cycloneDx(
				`{"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}`,
				`{"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}`,
				`{"type": "library", "group": "@babel", "name": "traverse", "version": "7.20.0", "purl": "pkg:npm/%40babel/traverse@7.20.0"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2021-23337", pkgName: "lodash", pkgVersion: "4.17.20", fixedVersion: "4.17.21", status: dbTypes.StatusFixed, severity: "HIGH", severitySource: vulnerability.GHSA, dataSourceId: vulnerability.GHSA},
				{vulnId: "GHSA-67hx-6x53-jw92", pkgName: "@babel/traverse", pkgVersion: "7.20.0", fixedVersion: "7.23.2", status: dbTypes.StatusFixed, severity: "CRITICAL", severitySource: vulnerability.GHSA, dataSourceId: vulnerability.GHSA},
			},
		},
		{
			name: "pip name normalization and maven purl name",
			sbom: cycloneDx(
				`{"type": "library", "name": "Django", "version": "4.2", "purl": "pkg:pypi/django@4.2"}`,
				`{"type": "library", "group": "org.apache.logging.log4j", "name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}`,
				`{"type": "library", "name": "golang.org/x/net", "version": "v0.10.0", "purl": "pkg:golang/golang.org/x/net@v0.10.0"}`,
				`{"type": "library", "name": "unknown", "version": "1.0.0", "purl": "pkg:generic/unknown@1.0.0"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2023-31047", pkgName: "Django", pkgVersion: "4.2", fixedVersion: "4.2.1, 4.1.9, 3.2.19", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.GHSA},
				{vulnId: "CVE-2021-44228", pkgName: "org.apache.logging.log4j:log4j-core", pkgVersion: "2.14.1", fixedVersion: "2.15.0, 2.3.1", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.GHSA},
				{vulnId: "CVE-2023-39325", pkgName: "golang.org/x/net", pkgVersion: "v0.10.0", fixedVersion: "0.17.0", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.GHSA},
			},
		},
		{
			name: "debian by source package (trivy properties)",
			sbom: cycloneDx(
				`{"type": "library", "name": "libssl3", "version": "3.0.11-1~deb12u1", "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?arch=amd64&distro=debian-12.4", "properties": [{"name": "aquasecurity:trivy:SrcName", "value": "openssl"}, {"name": "aquasecurity:trivy:SrcVersion", "value": "3.0.11"}, {"name": "aquasecurity:trivy:SrcRelease", "value": "1~deb12u1"}]}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2023-5678", pkgName: "libssl3", pkgVersion: "3.0.11-1~deb12u1", fixedVersion: "3.0.11-1~deb12u2", status: dbTypes.StatusFixed, severity: "LOW", severitySource: vulnerability.Debian, dataSourceId: vulnerability.Debian},
				{vulnId: "CVE-2023-9999", pkgName: "libssl3", pkgVersion: "3.0.11-1~deb12u1", status: dbTypes.StatusAffected, severity: "LOW", severitySource: vulnerability.Debian, dataSourceId: vulnerability.Debian},
			},
		},
		{
			name: "debian by source package (syft upstream) at fixed version",
			sbom: cycloneDx(
				`{"type": "library", "name": "libssl3", "version": "3.0.11-1~deb12u2", "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2023-9999", pkgName: "libssl3", pkgVersion: "3.0.11-1~deb12u2", status: dbTypes.StatusAffected, severity: "LOW", severitySource: vulnerability.Debian, dataSourceId: vulnerability.Debian},
			},
		},
		{
			name: "debian binary package without source info is not found",
			sbom: cycloneDx(
				`{"type": "library", "name": "libssl3", "version": "3.0.11-1~deb12u1", "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?arch=amd64&distro=debian-12"}`,
			),
		},
		{
			name: "os package without distro is skipped",
			sbom: cycloneDx(
				`{"type": "library", "name": "openssl", "version": "3.0.11-1~deb12u1", "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=amd64"}`,
			),
		},
		{
			name: "ubuntu",
			sbom: cycloneDx(
				`{"type": "library", "name": "openssl", "version": "3.0.2-0ubuntu1.12", "purl": "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.12?arch=amd64&distro=ubuntu-22.04"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2023-5678", pkgName: "openssl", pkgVersion: "3.0.2-0ubuntu1.12", fixedVersion: "3.0.2-0ubuntu1.13", status: dbTypes.StatusFixed, severity: "LOW", severitySource: vulnerability.Ubuntu, dataSourceId: vulnerability.Ubuntu},
			},
		},
		{
			name: "alpine by source package with minor release",
			sbom: cycloneDx(
				`{"type": "library", "name": "ssl_client", "version": "1.36.1-r15", "purl": "pkg:apk/alpine/ssl_client@1.36.1-r15?arch=x86_64&distro=alpine-3.18.4&upstream=busybox"}`,
				`{"type": "library", "name": "busybox", "version": "1.36.1-r16", "purl": "pkg:apk/alpine/busybox@1.36.1-r16?arch=x86_64&distro=alpine-3.18.4"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2023-42363", pkgName: "ssl_client", pkgVersion: "1.36.1-r15", fixedVersion: "1.36.1-r16", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.Alpine},
				{vulnId: "CVE-2023-42366", pkgName: "ssl_client", pkgVersion: "1.36.1-r15", fixedVersion: "1.36.1-r17", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.Alpine},
				{vulnId: "CVE-2023-42366", pkgName: "busybox", pkgVersion: "1.36.1-r16", fixedVersion: "1.36.1-r17", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.Alpine},
			},
		},
		{
			name: "wolfi has no release, is keyed by origin package and does not report unfixed advisories",
			sbom: cycloneDx(
				`{"type": "library", "name": "glibc", "version": "2.39-r4", "purl": "pkg:apk/wolfi/glibc@2.39-r4?arch=x86_64&distro=wolfi-20230201"}`,
				`{"type": "library", "name": "glibc-locale-posix", "version": "2.39-r4", "purl": "pkg:apk/wolfi/glibc-locale-posix@2.39-r4?arch=x86_64&distro=wolfi-20230201&upstream=glibc"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2024-2961", pkgName: "glibc", pkgVersion: "2.39-r4", fixedVersion: "2.39-r5", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.Wolfi},
				{vulnId: "CVE-2024-2961", pkgName: "glibc-locale-posix", pkgVersion: "2.39-r4", fixedVersion: "2.39-r5", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.Wolfi},
			},
		},
		{
			name: "red hat via default repositories, one advisory per cve, unfixed kept",
			sbom: cycloneDx(
				`{"type": "library", "name": "openssl-libs", "version": "1:3.0.7-24.el9_2", "purl": "pkg:rpm/redhat/openssl-libs@3.0.7-24.el9_2?arch=x86_64&distro=redhat-9.3&epoch=1"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2024-0001", pkgName: "openssl-libs", pkgVersion: "1:3.0.7-24.el9_2", fixedVersion: "1:3.0.7-25.el9_3", status: dbTypes.StatusFixed, severity: "HIGH", severitySource: vulnerability.RedHat, dataSourceId: vulnerability.RedHatOVAL},
				{vulnId: "CVE-2024-0002", pkgName: "openssl-libs", pkgVersion: "1:3.0.7-24.el9_2", status: dbTypes.StatusWillNotFix, severity: "LOW", severitySource: vulnerability.RedHat, dataSourceId: vulnerability.RedHatOVAL},
			},
		},
		{
			name: "centos uses the red hat advisories (syft spelling)",
			sbom: cycloneDx(
				`{"type": "library", "name": "openssl-libs", "version": "1:3.0.7-25.el9_3", "purl": "pkg:rpm/centos/openssl-libs@3.0.7-25.el9_3?arch=x86_64&distro=centos-9&epoch=1&upstream=openssl-3.0.7-25.el9_3.src.rpm"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2024-0002", pkgName: "openssl-libs", pkgVersion: "1:3.0.7-25.el9_3", status: dbTypes.StatusWillNotFix, severity: "LOW", severitySource: vulnerability.RedHat, dataSourceId: vulnerability.RedHatOVAL},
			},
		},
		{
			name: "red hat noarch matches any arch, unknown release is skipped, third-party release is skipped",
			sbom: cycloneDx(
				`{"type": "library", "name": "openssl-libs", "version": "1:3.0.7-24.el9_2", "purl": "pkg:rpm/redhat/openssl-libs@3.0.7-24.el9_2?arch=noarch&distro=redhat-9.3&epoch=1"}`,
				`{"type": "library", "name": "openssl-libs", "version": "1:3.0.7-24.el9_2", "purl": "pkg:rpm/redhat/openssl-libs@3.0.7-24.el9_2?arch=x86_64&distro=redhat-5.11&epoch=1"}`,
				`{"type": "library", "name": "openssl-libs", "version": "1:3.0.7-24.el9_2.remi", "purl": "pkg:rpm/redhat/openssl-libs@3.0.7-24.el9_2.remi?arch=x86_64&distro=redhat-9.3&epoch=1"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2024-0001", pkgName: "openssl-libs", pkgVersion: "1:3.0.7-24.el9_2", fixedVersion: "1:3.0.7-25.el9_3", status: dbTypes.StatusFixed, severity: "HIGH", severitySource: vulnerability.RedHat, dataSourceId: vulnerability.RedHatOVAL},
				{vulnId: "CVE-2024-0002", pkgName: "openssl-libs", pkgVersion: "1:3.0.7-24.el9_2", status: dbTypes.StatusWillNotFix, severity: "LOW", severitySource: vulnerability.RedHat, dataSourceId: vulnerability.RedHatOVAL},
				{vulnId: "CVE-2024-0003", pkgName: "openssl-libs", pkgVersion: "1:3.0.7-24.el9_2", fixedVersion: "1:3.0.7-30.el9_4", status: dbTypes.StatusFixed, severity: "MEDIUM", severitySource: vulnerability.RedHat, dataSourceId: vulnerability.RedHatOVAL},
			},
		},
		{
			name: "red hat build info replaces the default repositories",
			sbom: cycloneDx(
				`{"type": "library", "name": "openssl-libs", "version": "1:3.0.7-24.el9_2", "purl": "pkg:rpm/redhat/openssl-libs@3.0.7-24.el9_2?arch=x86_64&distro=redhat-9.3&epoch=1", "properties": [{"name": "aquasecurity:trivy:ContentSet", "value": "rhel-9-for-x86_64-appstream-rpms__9"}, {"name": "aquasecurity:trivy:NVR", "value": "ubi9-container-9.3-1361"}, {"name": "aquasecurity:trivy:Arch", "value": "x86_64"}]}`,
				`{"type": "library", "name": "openssl-libs", "version": "1:3.0.7-24.el9_2", "purl": "pkg:rpm/redhat/openssl-libs@3.0.7-24.el9_2?arch=x86_64&distro=redhat-9.3&epoch=1", "properties": [{"name": "aquasecurity:trivy:ContentSet", "value": "unknown-repo"}]}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2024-0002", pkgName: "openssl-libs", pkgVersion: "1:3.0.7-24.el9_2", status: dbTypes.StatusWillNotFix, severity: "LOW", severitySource: vulnerability.RedHat, dataSourceId: vulnerability.RedHatOVAL},
				{vulnId: "CVE-2024-0005", pkgName: "openssl-libs", pkgVersion: "1:3.0.7-24.el9_2", fixedVersion: "1:3.0.7-27.el9", status: dbTypes.StatusFixed, severity: "MEDIUM", severitySource: vulnerability.RedHat, dataSourceId: vulnerability.RedHatOVAL},
			},
		},
		{
			name: "rocky per-arch advisories",
			sbom: cycloneDx(
				`{"type": "library", "name": "bash", "version": "5.1.8-6.el9", "purl": "pkg:rpm/rocky/bash@5.1.8-6.el9?arch=x86_64&distro=rocky-9.3"}`,
				`{"type": "library", "name": "bash", "version": "5.1.8-6.el9", "purl": "pkg:rpm/rocky/bash@5.1.8-6.el9?distro=rocky-9.3"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2024-1000", pkgName: "bash", pkgVersion: "5.1.8-6.el9", fixedVersion: "5.1.8-9.el9", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.Rocky},
				{vulnId: "CVE-2024-1002", pkgName: "bash", pkgVersion: "5.1.8-6.el9", fixedVersion: "5.1.8-7.el9", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.Rocky},
				{vulnId: "CVE-2024-1002", pkgName: "bash", pkgVersion: "5.1.8-6.el9", fixedVersion: "5.1.8-7.el9", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.Rocky},
			},
		},
		{
			name: "oracle keeps the package's flavor",
			sbom: cycloneDx(
				`{"type": "library", "name": "openssl", "version": "1:1.1.1k-9.el8", "purl": "pkg:rpm/oracle/openssl@1.1.1k-9.el8?arch=x86_64&distro=oracle-8.9&epoch=1"}`,
				`{"type": "library", "name": "openssl", "version": "2:1.1.1k-9.ksplice1.el8", "purl": "pkg:rpm/ol/openssl@1.1.1k-9.ksplice1.el8?arch=x86_64&distro=ol-8.9&epoch=2"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2024-2000", pkgName: "openssl", pkgVersion: "1:1.1.1k-9.el8", fixedVersion: "1:1.1.1k-12.el8_9", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.OracleOVAL},
				{vulnId: "CVE-2024-2000", pkgName: "openssl", pkgVersion: "2:1.1.1k-9.ksplice1.el8", fixedVersion: "2:1.1.1k-12.ksplice1.el8_9", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.OracleOVAL},
			},
		},
		{
			name: "alma modular package",
			sbom: cycloneDx(
				`{"type": "library", "name": "npm", "version": "1:9.6.7-1.18.18.2.1.module_el9.2.0+41+3d4d3f7d", "purl": "pkg:rpm/alma/npm@9.6.7-1.18.18.2.1.module_el9.2.0%2B41%2B3d4d3f7d?arch=x86_64&distro=alma-9.2&epoch=1&modularitylabel=nodejs:18:9020020230427160308:rhel9"}`,
				`{"type": "library", "name": "npm", "version": "1:9.6.7-1.18.18.2.1.module_el9.2.0+41+3d4d3f7d", "purl": "pkg:rpm/alma/npm@9.6.7-1.18.18.2.1.module_el9.2.0%2B41%2B3d4d3f7d?arch=x86_64&distro=alma-9.2&epoch=1"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2024-3000", pkgName: "npm", pkgVersion: "1:9.6.7-1.18.18.2.1.module_el9.2.0+41+3d4d3f7d", fixedVersion: "1:9.6.7-1.18.18.2.1.module_el9.2.0+53+d1c9a4c9", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.Alma},
			},
		},
		{
			name: "amazon release normalization",
			sbom: cycloneDx(
				`{"type": "library", "name": "curl", "version": "8.3.0-1.amzn2023.0.1", "purl": "pkg:rpm/amzn/curl@8.3.0-1.amzn2023.0.1?arch=x86_64&distro=amzn-2023"}`,
				`{"type": "library", "name": "curl", "version": "7.61.1-11.90.amzn1", "purl": "pkg:rpm/amazon/curl@7.61.1-11.90.amzn1?arch=x86_64&distro=amazon-2018.03"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2023-38545", pkgName: "curl", pkgVersion: "8.3.0-1.amzn2023.0.1", fixedVersion: "8.3.0-1.amzn2023.0.2", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.Amazon},
				{vulnId: "CVE-2019-0001", pkgName: "curl", pkgVersion: "7.61.1-11.90.amzn1", fixedVersion: "7.61.1-11.91.amzn1", status: dbTypes.StatusFixed, severity: "", dataSourceId: vulnerability.Amazon},
			},
		},
		{
			name: "photon keeps the full release",
			sbom: cycloneDx(
				`{"type": "library", "name": "openssl-libs", "version": "3.0.11-1.ph4", "purl": "pkg:rpm/photon/openssl-libs@3.0.11-1.ph4?arch=x86_64&distro=photon-4.0&upstream=openssl-3.0.11-1.ph4.src.rpm"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2023-5678", pkgName: "openssl-libs", pkgVersion: "3.0.11-1.ph4", fixedVersion: "3.0.12-1.ph4", status: dbTypes.StatusFixed, severity: "MEDIUM", severitySource: vulnerability.NVD, dataSourceId: vulnerability.Photon},
			},
		},
		{
			name: "suse families",
			sbom: cycloneDx(
				`{"type": "library", "name": "openssl-3", "version": "3.0.8-150500.5.21.1", "purl": "pkg:rpm/suse/openssl-3@3.0.8-150500.5.21.1?arch=x86_64&distro=sles-15.5"}`,
				`{"type": "library", "name": "openssl-3", "version": "3.0.8-150500.5.21.1", "purl": "pkg:rpm/opensuse/openssl-3@3.0.8-150500.5.21.1?arch=x86_64&distro=opensuse-leap-15.5"}`,
			),
			expected: []expectedFinding{
				{vulnId: "CVE-2023-5678", pkgName: "openssl-3", pkgVersion: "3.0.8-150500.5.21.1", fixedVersion: "3.0.8-150500.5.24.1", status: dbTypes.StatusFixed, severity: "MEDIUM", severitySource: vulnerability.NVD, dataSourceId: vulnerability.SuseCVRF},
				{vulnId: "CVE-2023-5678", pkgName: "openssl-3", pkgVersion: "3.0.8-150500.5.21.1", fixedVersion: "3.0.8-150500.5.24.1", status: dbTypes.StatusFixed, severity: "MEDIUM", severitySource: vulnerability.NVD, dataSourceId: vulnerability.SuseCVRF},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) { //nolint:paralleltest // The cases share the process-wide database connection.
			findings, err := scanner.Scan([]byte(testCase.sbom))
			if testCase.err != nil {
				if !errors.Is(err, testCase.err) {
					t.Fatalf("expected error %v, got %v", testCase.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			assertFindings(t, findings, testCase.expected)
		})
	}
}

func assertFindings(t *testing.T, findings []*sbomScanningFinding.Finding, expected []expectedFinding) {
	t.Helper()

	var got []string
	for _, f := range findings {
		if f == nil || f.Vulnerability == nil || f.Package == nil {
			t.Fatalf("finding with nil vulnerability or package: %+v", f)
		}
		got = append(got, findingKey(f.Vulnerability.Id, f.Package.Name, f.Package.Version))
	}
	var want []string
	for _, e := range expected {
		want = append(want, findingKey(e.vulnId, e.pkgName, e.pkgVersion))
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("expected findings %v, got %v", want, got)
	}

	// Each expected finding claims one unclaimed actual finding with the same key and matching details, so that
	// duplicate keys (the same package listed twice) are each checked.
	claimed := make([]bool, len(findings))
	for _, e := range expected {
		var f *sbomScanningFinding.Finding
		for i, candidate := range findings {
			if claimed[i] || findingKey(candidate.Vulnerability.Id, candidate.Package.Name, candidate.Package.Version) != findingKey(e.vulnId, e.pkgName, e.pkgVersion) {
				continue
			}
			if candidate.FixedVersion == e.fixedVersion && candidate.Status == e.status && candidate.Vulnerability.Severity == e.severity && candidate.SeveritySource == e.severitySource && candidate.DataSource != nil && candidate.DataSource.ID == e.dataSourceId {
				f, claimed[i] = candidate, true
				break
			}
			if f == nil {
				f = candidate
			}
		}
		if f == nil {
			t.Fatalf("%s: finding not found", e.vulnId)
		}

		if f.FixedVersion != e.fixedVersion {
			t.Errorf("%s: expected fixed version %q, got %q", e.vulnId, e.fixedVersion, f.FixedVersion)
		}
		if f.Status != e.status {
			t.Errorf("%s: expected status %v, got %v", e.vulnId, e.status, f.Status)
		}
		if f.Vulnerability.Severity != e.severity {
			t.Errorf("%s: expected severity %q, got %q", e.vulnId, e.severity, f.Vulnerability.Severity)
		}
		if f.SeveritySource != e.severitySource {
			t.Errorf("%s: expected severity source %q, got %q", e.vulnId, e.severitySource, f.SeveritySource)
		}
		if f.DataSource == nil || f.DataSource.ID != e.dataSourceId {
			t.Errorf("%s: expected data source %q, got %+v", e.vulnId, e.dataSourceId, f.DataSource)
		}
	}
}

//nolint:paralleltest // The trivy-db connection is a process-wide singleton, so database-backed tests run one at a time.
func TestScannerScanFillsInfo(t *testing.T) {
	scanner := newTestScanner(t, fillTestDb(t))

	findings, err := scanner.Scan([]byte(cycloneDx(
		`{"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}`,
		`{"type": "library", "name": "libssl3", "version": "3.0.11-1~deb12u1", "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?arch=amd64&distro=debian-12&upstream=openssl"}`,
	)))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	byId := make(map[string]*sbomScanningFinding.Finding)
	for _, f := range findings {
		byId[f.Vulnerability.Id] = f
	}

	lodash, ok := byId["CVE-2021-23337"]
	if !ok {
		t.Fatalf("expected a lodash finding, got %+v", findings)
	}
	expectedLodash := &sbomScanningFinding.Finding{
		Vulnerability: &schema.Vulnerability{
			Id:             "CVE-2021-23337",
			Enumeration:    "CVE",
			Severity:       "HIGH",
			Description:    "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
			Reference:      "https://avd.aquasec.com/nvd/cve-2021-23337",
			Classification: "CVSS",
			Score:          &schema.VulnerabilityScore{Base: 7.2, Version: "3.1"},
			Scanner:        &schema.VulnerabilityScanner{Vendor: "GitHub Security Advisory npm"},
		},
		Package:          &schema.Package{Name: "lodash", Version: "4.17.20"},
		FixedVersion:     "4.17.21",
		SeveritySource:   vulnerability.GHSA,
		Status:           dbTypes.StatusFixed,
		DataSource:       &npmSource,
		Title:            "nodejs-lodash: command injection via template",
		CweIDs:           []string{"CWE-77"},
		References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-23337", "https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c"},
		PublishedDate:    &testPublished,
		LastModifiedDate: &testPublished,
	}
	assertFindingEqual(t, expectedLodash, lodash)

	openssl, ok := byId["CVE-2023-5678"]
	if !ok {
		t.Fatalf("expected an openssl finding, got %+v", findings)
	}
	// CVE ids always get the Aqua vulnerability database as primary url, whatever the data source.
	if openssl.Vulnerability.Reference != "https://avd.aquasec.com/nvd/cve-2023-5678" {
		t.Errorf("expected the avd url as primary url, got %q", openssl.Vulnerability.Reference)
	}
	if openssl.Vulnerability.Score == nil || openssl.Vulnerability.Score.Base != 5.3 {
		t.Errorf("expected the NVD score for a Debian finding, got %+v", openssl.Vulnerability.Score)
	}
}

func assertFindingEqual(t *testing.T, expected, got *sbomScanningFinding.Finding) {
	t.Helper()

	if *expected.Vulnerability.Score != *got.Vulnerability.Score {
		t.Errorf("score: expected %+v, got %+v", expected.Vulnerability.Score, got.Vulnerability.Score)
	}
	if *expected.Vulnerability.Scanner != *got.Vulnerability.Scanner {
		t.Errorf("scanner: expected %+v, got %+v", expected.Vulnerability.Scanner, got.Vulnerability.Scanner)
	}
	expectedVulnerability, gotVulnerability := *expected.Vulnerability, *got.Vulnerability
	expectedVulnerability.Score, gotVulnerability.Score = nil, nil
	expectedVulnerability.Scanner, gotVulnerability.Scanner = nil, nil
	if expectedVulnerability != gotVulnerability {
		t.Errorf("vulnerability: expected %+v, got %+v", expectedVulnerability, gotVulnerability)
	}
	if *expected.Package != *got.Package {
		t.Errorf("package: expected %+v, got %+v", expected.Package, got.Package)
	}
	if *expected.DataSource != *got.DataSource {
		t.Errorf("data source: expected %+v, got %+v", expected.DataSource, got.DataSource)
	}
	if expected.FixedVersion != got.FixedVersion || expected.SeveritySource != got.SeveritySource || expected.Status != got.Status || expected.Title != got.Title {
		t.Errorf("fields: expected %+v, got %+v", expected, got)
	}
	if !slices.Equal(expected.CweIDs, got.CweIDs) || !slices.Equal(expected.References, got.References) {
		t.Errorf("cwe ids/references: expected %v %v, got %v %v", expected.CweIDs, expected.References, got.CweIDs, got.References)
	}
	if got.PublishedDate == nil || !got.PublishedDate.Equal(*expected.PublishedDate) || got.LastModifiedDate == nil || !got.LastModifiedDate.Equal(*expected.LastModifiedDate) {
		t.Errorf("dates: expected %v %v, got %v %v", expected.PublishedDate, expected.LastModifiedDate, got.PublishedDate, got.LastModifiedDate)
	}
}

//nolint:paralleltest // The trivy-db connection is a process-wide singleton, so database-backed tests run one at a time.
func TestNewMissingDb(t *testing.T) {
	dbDir := filepath.Join(t.TempDir(), "missing")
	if _, err := New(dbDir); err == nil {
		t.Fatalf("expected an error for a missing database")
	}
	// A read-only scanner must not have created a database file.
	if _, err := os.Stat(db.Path(dbDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected no database file to be created, stat: %v", err)
	}
}
