package scanner

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/schema"
	sbomScanningErrors "github.com/altshiftab/sbom_scanning/pkg/errors"
	sbomScanningFinding "github.com/altshiftab/sbom_scanning/pkg/types/finding"
	sbomPackage "github.com/altshiftab/sbom_scanning/pkg/types/package"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/package-url/packageurl-go"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	bolt "go.etcd.io/bbolt"
)

func extractDistroVersion(distro, prefix string) string {
	if distro == "" {
		return ""
	}
	if strings.HasPrefix(distro, prefix) {
		return strings.TrimPrefix(distro, prefix)
	}
	// Maybe the distro is just a version number
	if prefix == "" {
		return distro
	}
	return ""
}

func majorVersion(v string) string {
	if idx := strings.IndexByte(v, '.'); idx != -1 {
		return v[:idx]
	}
	return v
}

func formatRPMVersion(p *packageurl.PackageURL) string {
	version := p.Version
	epoch := p.Qualifiers.Map()["epoch"]
	if epoch != "" && epoch != "0" {
		version = epoch + ":" + version
	}
	return version
}

func parseSbom(data []byte) ([]*sbomPackage.Package, error) {
	data = bytes.TrimLeft(data, " \t\r\n")
	if len(data) == 0 {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("data (trimmed)"))
	}

	if data[0] == '{' {
		// JSON: try CycloneDX first, then SPDX
		if pkgs, err := parseCycloneDXJSON(data); err == nil {
			return pkgs, nil
		}
		if pkgs, err := parseSPDXJSON(data); err == nil {
			return pkgs, nil
		}
		return nil, fmt.Errorf("unrecognized JSON SBOM format")
	}

	if data[0] == '<' {
		if pkgs, err := parseCycloneDXXML(data); err == nil {
			return pkgs, nil
		}
		return nil, fmt.Errorf("unrecognized XML SBOM format")
	}

	return nil, motmedelErrors.NewWithTrace(sbomScanningErrors.ErrUnexpectedSbomFormat)
}

func parseCycloneDXJSON(data []byte) ([]*sbomPackage.Package, error) {
	// Quick check: must contain bomFormat
	if !bytes.Contains(data, []byte(`"bomFormat"`)) {
		return nil, fmt.Errorf("not CycloneDX JSON")
	}

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("decode CycloneDX JSON: %w", err))
	}
	return extractCycloneDXPackages(bom), nil
}

func parseCycloneDXXML(data []byte) ([]*sbomPackage.Package, error) {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatXML)
	if err := decoder.Decode(bom); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("decode CycloneDX XML: %w", err))
	}
	return extractCycloneDXPackages(bom), nil
}

func extractCycloneDXPackages(bom *cdx.BOM) []*sbomPackage.Package {
	if bom.Components == nil {
		return nil
	}
	var pkgs []*sbomPackage.Package
	for _, comp := range *bom.Components {
		if comp.PackageURL == "" || comp.Version == "" {
			continue
		}
		p, err := packageurl.FromString(comp.PackageURL)
		if err != nil {
			continue
		}
		pkgs = append(pkgs, &sbomPackage.Package{
			Name:    comp.Name,
			Version: comp.Version,
			Purl:    &p,
		})
	}
	return pkgs
}

func parseSPDXJSON(data []byte) ([]*sbomPackage.Package, error) {
	// Quick check: must contain spdxVersion
	if !bytes.Contains(data, []byte(`"spdxVersion"`)) {
		return nil, fmt.Errorf("not SPDX JSON")
	}

	doc, err := spdxjson.Read(bytes.NewReader(data))
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("decode SPDX JSON: %w", err))
	}
	return extractSPDXPackages(doc), nil
}

func extractSPDXPackages(doc *spdx.Document) []*sbomPackage.Package {
	var pkgs []*sbomPackage.Package
	for _, p := range doc.Packages {
		if p.PackageVersion == "" {
			continue
		}

		var purl *packageurl.PackageURL
		for _, ref := range p.PackageExternalReferences {
			if ref.RefType == "purl" || ref.RefType == packageurl.TypeGeneric {
				parsed, err := packageurl.FromString(ref.Locator)
				if err == nil {
					purl = &parsed
					break
				}
			}
		}

		if purl == nil {
			continue
		}

		pkgs = append(pkgs, &sbomPackage.Package{
			Name:    p.PackageName,
			Version: p.PackageVersion,
			Purl:    purl,
		})
	}
	return pkgs
}

// purlToEcosystem maps PURL type to ecosystem and version matcher.
func purlToLangEcosystem(purlType string) (ecosystem.Type, matchVersionFunc, bool) {
	switch purlType {
	case packageurl.TypeNPM:
		return ecosystem.Npm, matchNpm, true
	case packageurl.TypePyPi:
		return ecosystem.Pip, matchPep440, true
	case packageurl.TypeGem:
		return ecosystem.RubyGems, matchRubygems, true
	case packageurl.TypeMaven:
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
		return ecosystem.Cocoapods, matchRubygems, true
	case "pub":
		return ecosystem.Pub, matchGeneric, true
	case packageurl.TypeHex:
		return ecosystem.Erlang, matchGeneric, true
	case packageurl.TypeConan:
		return ecosystem.Conan, matchGeneric, true
	case "bitnami":
		return ecosystem.Bitnami, matchBitnami, true
	default:
		return "", nil, false
	}
}

// purlToOSInfo extracts OS ecosystem info from PURL qualifiers.
func purlToOSInfo(p *packageurl.PackageURL) (bucketName string, lessThan func(string, string) (bool, error), ok bool) {
	distro := p.Qualifiers.Map()["distro"]

	switch p.Type {
	case "apk":
		version := extractDistroVersion(distro, "alpine-")
		if version == "" {
			return "", nil, false
		}
		// Alpine bucket: "alpine X.Y"
		parts := strings.SplitN(version, ".", 3)
		if len(parts) >= 2 {
			version = parts[0] + "." + parts[1]
		}
		return ecosystem.Alpine.String() + " " + version, apkLessThan, true

	case "deb":
		ns := p.Namespace // e.g. "debian" or "ubuntu"
		version := extractDistroVersion(distro, ns+"-")
		if version == "" {
			return "", nil, false
		}
		switch ns {
		case "debian":
			return ecosystem.Debian.String() + " " + majorVersion(version), debLessThan, true
		case "ubuntu":
			return ecosystem.Ubuntu.String() + " " + version, debLessThan, true
		default:
			return "", nil, false
		}

	case "rpm":
		ns := p.Namespace // e.g. "redhat", "centos", "rocky", etc.
		version := extractDistroVersion(distro, ns+"-")
		if version == "" {
			// Try common prefixes
			for _, prefix := range []string{"rhel-", "el", "centos-"} {
				version = extractDistroVersion(distro, prefix)
				if version != "" {
					break
				}
			}
		}
		if version == "" {
			return "", nil, false
		}
		major := majorVersion(version)
		switch ns {
		case "redhat", "centos":
			return "Red Hat " + major, rpmLessThan, true
		case "rocky":
			return ecosystem.Rocky.String() + " " + major, rpmLessThan, true
		case "alma", "almalinux":
			return ecosystem.AlmaLinux.String() + " " + major, rpmLessThan, true
		case "amazon", "amzn":
			return "amazon linux " + major, rpmLessThan, true
		case "oracle", "oraclelinux":
			return "Oracle Linux " + major, rpmLessThan, true
		case "suse", "opensuse":
			return "SUSE Linux Enterprise " + major, rpmLessThan, true
		case "photon":
			return "Photon OS " + major, rpmLessThan, true
		default:
			return "", nil, false
		}

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

func autoDetectSeverity(vulnID string, vuln *dbTypes.Vulnerability, dataSourceID dbTypes.SourceID) (string, dbTypes.SourceID) {
	if vs, ok := vuln.VendorSeverity[dataSourceID]; ok {
		return vs.String(), dataSourceID
	}

	sources := []dbTypes.SourceID{vulnerability.NVD}
	if strings.HasPrefix(vulnID, "GHSA-") {
		sources = []dbTypes.SourceID{vulnerability.GHSA, vulnerability.NVD}
	}

	for _, source := range sources {
		if vs, ok := vuln.VendorSeverity[source]; ok {
			return vs.String(), source
		}
	}

	// Fall back to the precomputed severity field
	if vuln.Severity != "" {
		return vuln.Severity, ""
	}

	return dbTypes.SeverityUnknown.String(), ""
}

func detectEnumeration(vulnID string) string {
	if idx := strings.IndexByte(vulnID, '-'); idx != -1 {
		return vulnID[:idx]
	}
	return ""
}

func autoDetectCVSS(vuln *dbTypes.Vulnerability, severitySource, dataSourceID dbTypes.SourceID) (dbTypes.CVSS, bool) {
	if cvss, ok := vuln.CVSS[severitySource]; ok {
		return cvss, true
	}
	if cvss, ok := vuln.CVSS[dataSourceID]; ok {
		return cvss, true
	}
	if cvss, ok := vuln.CVSS[vulnerability.NVD]; ok {
		return cvss, true
	}
	return dbTypes.CVSS{}, false
}

func getPrimaryURL(vulnID string, refs []string, source dbTypes.SourceID) string {
	switch {
	case strings.HasPrefix(vulnID, "CVE-"):
		return "https://avd.aquasec.com/nvd/" + strings.ToLower(vulnID)
	case strings.HasPrefix(vulnID, "RUSTSEC-"):
		return "https://osv.dev/vulnerability/" + vulnID
	case strings.HasPrefix(vulnID, "GHSA-"):
		return "https://github.com/advisories/" + vulnID
	case strings.HasPrefix(vulnID, "TEMP-"):
		return "https://security-tracker.debian.org/tracker/" + vulnID
	}

	prefixes := map[dbTypes.SourceID][]string{
		vulnerability.Debian: {"http://www.debian.org", "https://www.debian.org"},
		vulnerability.Ubuntu: {"http://www.ubuntu.com", "https://usn.ubuntu.com"},
		vulnerability.RedHat: {"https://access.redhat.com"},
	}
	if pp, ok := prefixes[source]; ok {
		for _, pre := range pp {
			for _, ref := range refs {
				if strings.HasPrefix(ref, pre) {
					return ref
				}
			}
		}
	}
	return ""
}

// detectSBOMFormat is a helper for callers who want to know the format without scanning.
func detectSBOMFormat(data []byte) string {
	data = bytes.TrimLeft(data, " \t\r\n")
	if len(data) == 0 {
		return ""
	}
	if data[0] == '{' {
		var probe struct {
			BOMFormat   string `json:"bomFormat"`
			SpdxVersion string `json:"spdxVersion"`
		}
		if json.Unmarshal(data, &probe) == nil {
			if probe.BOMFormat == "CycloneDX" {
				return "cyclonedx-json"
			}
			if probe.SpdxVersion != "" {
				return "spdx-json"
			}
		}
	}
	if data[0] == '<' {
		return "cyclonedx-xml"
	}
	return ""
}

type Scanner struct {
	dbc db.Config
}

func (s *Scanner) Close() error {
	return db.Close()
}

func (s *Scanner) Scan(data []byte) ([]*sbomScanningFinding.Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}

	packages, err := parseSbom(data)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("parse sbom: %w", err))
	}

	var findings []*sbomScanningFinding.Finding
	for _, p := range packages {
		detected, err := s.detectVulnerabilities(p)
		if err != nil {
			return nil, motmedelErrors.NewWithTrace(fmt.Errorf("detect vulns for %s: %w", p.Name, err))
		}
		findings = append(findings, detected...)
	}

	s.fillInfo(findings)

	return findings, nil
}

func (s *Scanner) detectVulnerabilities(p *sbomPackage.Package) ([]*sbomScanningFinding.Finding, error) {
	if p.Purl == nil {
		return nil, nil
	}

	// Try language ecosystem first
	if eco, match, ok := purlToLangEcosystem(p.Purl.Type); ok {
		return s.detectLangVulns(p, eco, match)
	}

	// Try OS ecosystem
	if bucketName, lessThan, ok := purlToOSInfo(p.Purl); ok {
		return s.detectOSVulns(p, bucketName, lessThan)
	}

	return nil, nil
}

func (s *Scanner) detectLangVulns(p *sbomPackage.Package, eco ecosystem.Type, match matchVersionFunc) ([]*sbomScanningFinding.Finding, error) {
	prefix := fmt.Sprintf("%s::", eco)
	pkgName := vulnerability.NormalizePkgName(eco, p.Name)

	advisories, err := s.dbc.GetAdvisories(prefix, pkgName)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("get advisories for %s: %w", pkgName, err))
	}

	var findings []*sbomScanningFinding.Finding
	for _, adv := range advisories {
		if !isVulnerable(p.Version, adv, match) {
			continue
		}
		findings = append(findings, &sbomScanningFinding.Finding{
			Vulnerability: &schema.Vulnerability{
				Id: adv.VulnerabilityID,
			},
			Package: &schema.Package{
				Name:    p.Name,
				Version: p.Version,
			},
			FixedVersion: createFixedVersions(adv),
			DataSource:   adv.DataSource,
		})
	}
	return findings, nil
}

func (s *Scanner) detectOSVulns(p *sbomPackage.Package, bucketName string, lessThan func(string, string) (bool, error)) ([]*sbomScanningFinding.Finding, error) {
	packageName := p.Name
	// For RPM packages, use the PURL name (without namespace prefix)
	if p.Purl.Type == "rpm" {
		packageName = p.Purl.Name
	}

	advisories, err := s.dbc.GetAdvisories(bucketName, packageName)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("get advisories for %s (%s): %w", packageName, bucketName, err))
	}

	installedVersion := p.Version
	if p.Purl.Type == "rpm" {
		installedVersion = formatRPMVersion(p.Purl)
	}

	var findings []*sbomScanningFinding.Finding
	for _, advisory := range advisories {
		if !isOSVulnerable(installedVersion, advisory.FixedVersion, lessThan) {
			continue
		}
		findings = append(
			findings,
			&sbomScanningFinding.Finding{
				Vulnerability: &schema.Vulnerability{
					Id: advisory.VulnerabilityID,
				},
				Package: &schema.Package{
					Name:    packageName,
					Version: installedVersion,
				},
				FixedVersion: advisory.FixedVersion,
				Status:       advisory.Status,
				DataSource:   advisory.DataSource,
			},
		)
	}
	return findings, nil
}

// fillInfo enriches detected findings with details from the DB.
func (s *Scanner) fillInfo(findings []*sbomScanningFinding.Finding) {
	for _, f := range findings {
		if f.FixedVersion != "" {
			f.Status = dbTypes.StatusFixed
		} else if f.Status == dbTypes.StatusUnknown {
			f.Status = dbTypes.StatusAffected
		}

		vuln, err := s.dbc.GetVulnerability(f.Vulnerability.Id)
		if err != nil {
			continue
		}

		dataSourceID := dbTypes.SourceID("")
		if f.DataSource != nil {
			dataSourceID = cmp.Or(f.DataSource.BaseID, f.DataSource.ID)
		}

		severity, severitySource := autoDetectSeverity(f.Vulnerability.Id, &vuln, dataSourceID)

		f.Vulnerability.Severity = severity
		f.SeveritySource = severitySource
		f.Vulnerability.Reference = getPrimaryURL(f.Vulnerability.Id, vuln.References, dataSourceID)
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

		if cvss, ok := autoDetectCVSS(&vuln, severitySource, dataSourceID); ok {
			score := &schema.VulnerabilityScore{Base: cvss.V3Score}
			version := "3.1"
			if cvss.V40Score != 0 {
				score.Base = cvss.V40Score
				version = "4.0"
			} else if cvss.V3Score == 0 && cvss.V2Score != 0 {
				score.Base = cvss.V2Score
				version = "2.0"
			}
			score.Version = version
			f.Vulnerability.Score = score
			f.Vulnerability.Classification = "CVSS"
		}
	}
}

func New(dbDir string) (*Scanner, error) {
	if err := db.Init(dbDir, db.WithBoltOptions(&bolt.Options{ReadOnly: true})); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("init trivy db: %w", err))
	}
	return &Scanner{dbc: db.Config{}}, nil
}
