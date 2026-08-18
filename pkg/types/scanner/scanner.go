package scanner

import (
	"cmp"
	"fmt"
	"strings"
	"time"

	"github.com/altshiftab/sbom_scanning/pkg/sbom"
	sbomScanningFinding "github.com/altshiftab/sbom_scanning/pkg/types/finding"
	sbomPackage "github.com/altshiftab/sbom_scanning/pkg/types/package"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/package-url/packageurl-go"
	bolt "go.etcd.io/bbolt"
)

// dbOpenTimeout bounds the wait for the database file lock, so a scanner does not hang behind a database update.
const dbOpenTimeout = 5 * time.Second

// purlToLangEcosystem maps a PURL type to the advisory ecosystem and the version matcher its constraints are written
// for, as Trivy's library detector does.
func purlToLangEcosystem(purlType string) (ecosystem.Type, matchVersionFunc, bool) {
	switch purlType {
	case packageurl.TypeNPM:
		return ecosystem.Npm, matchNpm, true
	case packageurl.TypePyPi:
		return ecosystem.Pip, matchPep440, true
	case packageurl.TypeGem:
		return ecosystem.RubyGems, matchRubygems, true
	case packageurl.TypeMaven, "gradle":
		return ecosystem.Maven, matchMaven, true
	case packageurl.TypeCargo:
		return ecosystem.Cargo, matchGeneric, true
	case packageurl.TypeGolang:
		return ecosystem.Go, matchGeneric, true
	case packageurl.TypeNuget:
		return ecosystem.NuGet, matchGeneric, true
	case packageurl.TypeComposer:
		return ecosystem.Composer, matchGeneric, true
	case packageurl.TypeSwift:
		return ecosystem.Swift, matchGeneric, true
	case packageurl.TypeCocoapods:
		// CocoaPods uses RubyGems version specifiers.
		return ecosystem.Cocoapods, matchRubygems, true
	case packageurl.TypePub:
		return ecosystem.Pub, matchGeneric, true
	case packageurl.TypeHex:
		return ecosystem.Erlang, matchGeneric, true
	case packageurl.TypeConan:
		return ecosystem.Conan, matchGeneric, true
	case packageurl.TypeBitnami:
		return ecosystem.Bitnami, matchBitnami, true
	case "julia":
		return ecosystem.Julia, matchGeneric, true
	default:
		return "", nil, false
	}
}

func createFixedVersions(advisory dbTypes.Advisory) string {
	if len(advisory.PatchedVersions) != 0 {
		return joinUnique(advisory.PatchedVersions)
	}

	var fixedVersions []string
	for _, v := range advisory.VulnerableVersions {
		for s := range strings.SplitSeq(v, ",") {
			s = strings.TrimSpace(s)
			if !strings.HasPrefix(s, "<=") && strings.HasPrefix(s, "<") {
				s = strings.TrimPrefix(s, "<")
				fixedVersions = append(fixedVersions, strings.TrimSpace(s))
			}
		}
	}
	return joinUnique(fixedVersions)
}

func joinUnique(ss []string) string {
	seen := make(map[string]struct{}, len(ss))
	var unique []string
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			unique = append(unique, s)
		}
	}
	return strings.Join(unique, ", ")
}

// autoDetectSeverity picks the severity the way Trivy's "auto" severity source does: the advisory's own data source
// first, then GitHub for GHSA IDs, then NVD, and finally the precomputed severity.
func autoDetectSeverity(vulnId string, vuln *dbTypes.Vulnerability, dataSourceId dbTypes.SourceID) (string, dbTypes.SourceID) {
	if vs, ok := vuln.VendorSeverity[dataSourceId]; ok {
		return vs.String(), dataSourceId
	}

	sources := []dbTypes.SourceID{vulnerability.NVD}
	if strings.HasPrefix(vulnId, "GHSA-") {
		sources = []dbTypes.SourceID{vulnerability.GHSA, vulnerability.NVD}
	}

	for _, source := range sources {
		if vs, ok := vuln.VendorSeverity[source]; ok {
			return vs.String(), source
		}
	}

	if vuln.Severity != "" {
		return vuln.Severity, ""
	}

	return dbTypes.SeverityUnknown.String(), ""
}

func detectEnumeration(vulnId string) string {
	if idx := strings.IndexByte(vulnId, '-'); idx != -1 {
		return vulnId[:idx]
	}
	return ""
}

func autoDetectCVSS(vuln *dbTypes.Vulnerability, severitySource, dataSourceId dbTypes.SourceID) (dbTypes.CVSS, bool) {
	for _, source := range []dbTypes.SourceID{severitySource, dataSourceId, vulnerability.NVD} {
		if cvss, ok := vuln.CVSS[source]; ok {
			return cvss, true
		}
	}
	return dbTypes.CVSS{}, false
}

// cvssScore picks the newest CVSS version the source scored, naming the version from the vector where it says so
// ("CVSS:3.0/..." versus "CVSS:3.1/...").
func cvssScore(cvss dbTypes.CVSS) *schema.VulnerabilityScore {
	score, vector, fallbackVersion := cvss.V40Score, cvss.V40Vector, "4.0"
	switch {
	case cvss.V40Score != 0:
	case cvss.V3Score != 0:
		score, vector, fallbackVersion = cvss.V3Score, cvss.V3Vector, "3.1"
	case cvss.V2Score != 0:
		score, vector, fallbackVersion = cvss.V2Score, cvss.V2Vector, "2.0"
	default:
		return nil
	}

	version := fallbackVersion
	if v, ok := strings.CutPrefix(vector, "CVSS:"); ok {
		if v, _, ok = strings.Cut(v, "/"); ok && v != "" {
			version = v
		}
	}

	return &schema.VulnerabilityScore{Base: score, Version: version}
}

// primaryUrlPrefixes are the reference URLs preferred as the primary one for advisories from a data source.
var primaryUrlPrefixes = map[dbTypes.SourceID][]string{
	vulnerability.Debian: {"http://www.debian.org", "https://www.debian.org"},
	vulnerability.Ubuntu: {"http://www.ubuntu.com", "https://usn.ubuntu.com"},
	vulnerability.RedHat: {"https://access.redhat.com"},
}

func getPrimaryUrl(vulnId string, refs []string, source dbTypes.SourceID) string {
	switch {
	case strings.HasPrefix(vulnId, "CVE-"):
		return "https://avd.aquasec.com/nvd/" + strings.ToLower(vulnId)
	case strings.HasPrefix(vulnId, "RUSTSEC-"):
		return "https://osv.dev/vulnerability/" + vulnId
	case strings.HasPrefix(vulnId, "GHSA-"):
		return "https://github.com/advisories/" + vulnId
	case strings.HasPrefix(vulnId, "TEMP-"):
		return "https://security-tracker.debian.org/tracker/" + vulnId
	}

	for _, prefix := range primaryUrlPrefixes[source] {
		for _, ref := range refs {
			if strings.HasPrefix(ref, prefix) {
				return ref
			}
		}
	}
	return ""
}

// Scanner matches the packages of an SBOM against a Trivy vulnerability database. The database connection is a
// package-level singleton in trivy-db, so New must not be called for a second directory while a Scanner is in use, and
// Close closes the connection for every Scanner.
type Scanner struct {
	dbc db.Config
}

func New(dbDir string) (*Scanner, error) {
	if err := db.Init(dbDir, db.WithBoltOptions(&bolt.Options{ReadOnly: true, Timeout: dbOpenTimeout})); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("init trivy db: %w", err), dbDir)
	}
	return &Scanner{dbc: db.Config{}}, nil
}

func (s *Scanner) Close() error {
	if err := db.Close(); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("close trivy db: %w", err))
	}
	return nil
}

// Scan reports the known vulnerabilities of the packages in a CycloneDX (JSON or XML) or SPDX (JSON) SBOM. Malformed
// input yields an error wrapping altshiftErrors.ErrParseError.
func (s *Scanner) Scan(data []byte) ([]*sbomScanningFinding.Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}

	packages, err := sbom.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("sbom parse: %w", err)
	}

	var findings []*sbomScanningFinding.Finding
	for _, p := range packages {
		detected, err := s.detectVulnerabilities(p)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("detect vulnerabilities (%s): %w", p.Name, err), p)
		}
		findings = append(findings, detected...)
	}

	s.fillInfo(findings)

	return findings, nil
}

func (s *Scanner) detectVulnerabilities(p *sbomPackage.Package) ([]*sbomScanningFinding.Finding, error) {
	if p == nil || p.Purl == nil {
		return nil, nil
	}

	if eco, match, ok := purlToLangEcosystem(p.Purl.Type); ok {
		return s.detectLangVulnerabilities(p, eco, match)
	}

	if info, ok := purlOsInfo(p.Purl); ok {
		return s.detectOsVulnerabilities(p, info)
	}

	return nil, nil
}

func (s *Scanner) detectLangVulnerabilities(p *sbomPackage.Package, eco ecosystem.Type, match matchVersionFunc) ([]*sbomScanningFinding.Finding, error) {
	// The advisories of an ecosystem live in buckets prefixed with the ecosystem, e.g. "npm::Node.js Vulnerability
	// Database"; the prefix reaches all data sources of the ecosystem.
	prefix := fmt.Sprintf("%s::", eco)
	pkgName := vulnerability.NormalizePkgName(eco, p.Name)

	advisories, err := s.dbc.GetAdvisories(prefix, pkgName)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("get advisories (%s %s): %w", eco, pkgName, err), pkgName)
	}

	var findings []*sbomScanningFinding.Finding
	for _, advisory := range advisories {
		if !isVulnerable(p.Version, advisory, match) {
			continue
		}
		findings = append(findings, &sbomScanningFinding.Finding{
			Vulnerability: &schema.Vulnerability{Id: advisory.VulnerabilityID},
			Package: &schema.Package{
				Name:    p.Name,
				Version: p.Version,
			},
			FixedVersion: createFixedVersions(advisory),
			DataSource:   advisory.DataSource,
		})
	}
	return findings, nil
}

// fillInfo enriches detected findings with the vulnerability details from the database: severity, description,
// references, CVSS score and dates.
func (s *Scanner) fillInfo(findings []*sbomScanningFinding.Finding) {
	for _, f := range findings {
		// Some vendors (Red Hat) have their own vulnerability status; otherwise it follows from the fixed version.
		if f.FixedVersion != "" {
			f.Status = dbTypes.StatusFixed
		} else if f.Status == dbTypes.StatusUnknown {
			f.Status = dbTypes.StatusAffected
		}

		vuln, err := s.dbc.GetVulnerability(f.Vulnerability.Id)
		if err != nil {
			// The CVE may have been rejected; the finding keeps what the advisory gave it.
			continue
		}

		var dataSourceId, baseSourceId dbTypes.SourceID
		if f.DataSource != nil {
			dataSourceId = f.DataSource.ID
			// The base source decides the severity, e.g. Debian's severity for Root.io advisories.
			baseSourceId = cmp.Or(f.DataSource.BaseID, f.DataSource.ID)
		}

		severity, severitySource := autoDetectSeverity(f.Vulnerability.Id, &vuln, baseSourceId)
		// A vendor may have set a package-specific severity (Debian, Red Hat); that one is kept.
		if f.SeveritySource != "" {
			severity, severitySource = f.Vulnerability.Severity, f.SeveritySource
		}

		f.Vulnerability.Severity = severity
		f.SeveritySource = severitySource
		f.Vulnerability.Reference = getPrimaryUrl(f.Vulnerability.Id, vuln.References, dataSourceId)
		f.Vulnerability.Description = vuln.Description
		f.Vulnerability.Enumeration = detectEnumeration(f.Vulnerability.Id)

		if f.DataSource != nil && f.DataSource.Name != "" {
			f.Vulnerability.Scanner = &schema.VulnerabilityScanner{Vendor: f.DataSource.Name}
		}

		f.Title = vuln.Title
		f.CweIDs = vuln.CweIDs
		f.References = vuln.References
		f.PublishedDate = vuln.PublishedDate
		f.LastModifiedDate = vuln.LastModifiedDate

		if cvss, ok := autoDetectCVSS(&vuln, severitySource, baseSourceId); ok {
			if score := cvssScore(cvss); score != nil {
				f.Vulnerability.Score = score
				f.Vulnerability.Classification = "CVSS"
			}
		}
	}
}
