package scanner

import (
	"cmp"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	sbomScanningFinding "github.com/altshiftab/sbom_scanning/pkg/types/finding"
	sbomPackage "github.com/altshiftab/sbom_scanning/pkg/types/package"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/schema"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	rpm "github.com/knqyf263/go-rpm-version"
	"github.com/package-url/packageurl-go"
)

// The OS-package detection mirrors Trivy's pkg/detector/ospkg scanners: which advisory bucket a distribution release
// maps to, which name (binary or source package) the advisories are keyed by, and how versions are compared.

type osFamily string

const (
	osFamilyAlpine             osFamily = "alpine"
	osFamilyWolfi              osFamily = "wolfi"
	osFamilyChainguard         osFamily = "chainguard"
	osFamilyDebian             osFamily = "debian"
	osFamilyUbuntu             osFamily = "ubuntu"
	osFamilyRedHat             osFamily = "redhat"
	osFamilyRocky              osFamily = "rocky"
	osFamilyAlma               osFamily = "alma"
	osFamilyOracle             osFamily = "oracle"
	osFamilyAmazon             osFamily = "amazon"
	osFamilyPhoton             osFamily = "photon"
	osFamilySles               osFamily = "sles"
	osFamilySleMicro           osFamily = "slem"
	osFamilyOpenSuseLeap       osFamily = "opensuse-leap"
	osFamilyOpenSuseTumbleweed osFamily = "opensuse-tumbleweed"
)

// osFamilyAliases maps the family spellings found in PURL distro qualifiers and namespaces, as Trivy and Syft write
// them, to the family. CentOS is scanned with the Red Hat advisories, as Trivy does.
var osFamilyAliases = map[string]osFamily{
	"alpine":              osFamilyAlpine,
	"wolfi":               osFamilyWolfi,
	"chainguard":          osFamilyChainguard,
	"debian":              osFamilyDebian,
	"ubuntu":              osFamilyUbuntu,
	"redhat":              osFamilyRedHat,
	"rhel":                osFamilyRedHat,
	"centos":              osFamilyRedHat,
	"rocky":               osFamilyRocky,
	"rockylinux":          osFamilyRocky,
	"alma":                osFamilyAlma,
	"almalinux":           osFamilyAlma,
	"oracle":              osFamilyOracle,
	"oraclelinux":         osFamilyOracle,
	"ol":                  osFamilyOracle,
	"amazon":              osFamilyAmazon,
	"amzn":                osFamilyAmazon,
	"photon":              osFamilyPhoton,
	"sles":                osFamilySles,
	"suse":                osFamilySles,
	"slem":                osFamilySleMicro,
	"sle-micro":           osFamilySleMicro,
	"opensuse":            osFamilyOpenSuseLeap,
	"opensuse-leap":       osFamilyOpenSuseLeap,
	"opensuse.leap":       osFamilyOpenSuseLeap,
	"opensuse-tumbleweed": osFamilyOpenSuseTumbleweed,
	"opensuse.tumbleweed": osFamilyOpenSuseTumbleweed,
}

// osFamilyAliasesLongestFirst orders the aliases so that a prefix match prefers "opensuse-leap" over "opensuse".
var osFamilyAliasesLongestFirst = func() []string {
	aliases := make([]string, 0, len(osFamilyAliases))
	for alias := range osFamilyAliases {
		aliases = append(aliases, alias)
	}
	slices.SortFunc(aliases, func(a, b string) int {
		return cmp.Or(cmp.Compare(len(b), len(a)), cmp.Compare(a, b))
	})
	return aliases
}()

// redHatDefaultContentSets are the repositories Trivy assumes for a Red Hat release when the package carries no build
// info; the Red Hat advisories are keyed by the CPEs those repositories map to. Release 10 follows the pattern of 8
// and 9 (Trivy's own table stops at 9); it only yields findings once the database maps those repositories.
var redHatDefaultContentSets = map[string][]string{
	"6":  {"rhel-6-server-rpms", "rhel-6-server-extras-rpms"},
	"7":  {"rhel-7-server-rpms", "rhel-7-server-extras-rpms"},
	"8":  {"rhel-8-for-x86_64-baseos-rpms", "rhel-8-for-x86_64-appstream-rpms"},
	"9":  {"rhel-9-for-x86_64-baseos-rpms", "rhel-9-for-x86_64-appstream-rpms"},
	"10": {"rhel-10-for-x86_64-baseos-rpms", "rhel-10-for-x86_64-appstream-rpms"},
}

// redHatGenericContentSetSuffix matches the "__8"/"__9"/"__10" suffixes Red Hat image builds append to content sets,
// which are not repository names, while leaving EUS suffixes such as "__9_DOT_2" alone.
var redHatGenericContentSetSuffix = regexp.MustCompile(`__\d+$`)

// redHatExcludedReleaseSuffixes mark packages from third-party repositories that Red Hat's advisories do not cover.
var redHatExcludedReleaseSuffixes = []string{".remi"}

type osInfo struct {
	family  osFamily
	version string
}

// purlOsInfo reads the distribution from an OS package's PURL: the "distro" qualifier ("<family>-<version>", as Trivy
// and Syft write it), with the namespace naming the family when the qualifier holds a bare version.
func purlOsInfo(purl *packageurl.PackageURL) (*osInfo, bool) {
	distro := strings.ToLower(purl.Qualifiers.Map()["distro"])
	if distro == "" {
		return nil, false
	}

	for _, alias := range osFamilyAliasesLongestFirst {
		if distro == alias {
			return &osInfo{family: osFamilyAliases[alias]}, true
		}
		if version, ok := strings.CutPrefix(distro, alias+"-"); ok {
			return &osInfo{family: osFamilyAliases[alias], version: version}, true
		}
	}

	if family, ok := osFamilyAliases[strings.ToLower(purl.Namespace)]; ok {
		return &osInfo{family: family, version: distro}, true
	}

	return nil, false
}

func majorVersion(v string) string {
	major, _, _ := strings.Cut(v, ".")
	return major
}

func minorVersion(v string) string {
	major, rest, ok := strings.Cut(v, ".")
	if !ok {
		return v
	}
	minor, _, _ := strings.Cut(rest, ".")
	return major + "." + minor
}

// amazonRelease normalizes an Amazon Linux version to the release the advisories are bucketed by ("1", "2", "2022",
// "2023"); the first generation reported dated versions such as "2018.03".
func amazonRelease(v string) string {
	release, _, _ := strings.Cut(v, " ")
	release = majorVersion(release)
	if release != "2" && release != "2022" && release != "2023" {
		return "1"
	}
	return release
}

// addModularNamespace prefixes a package name with its module stream the way the Red Hat family advisories key
// modular packages: "npm" with label "nodejs:12:8030020201124152102:229f0a1c" becomes "nodejs:12::npm".
func addModularNamespace(name, label string) string {
	var count int
	for i, r := range label {
		if r == ':' {
			count++
		}
		if count == 2 {
			return label[:i] + "::" + name
		}
	}
	return name
}

// rpmRelease is the release part of an RPM version ("1.2.3-4.el9" -> "4.el9").
func rpmRelease(version string) string {
	v := rpm.NewVersion(version)
	return v.Release()
}

// oraclePackageFlavor tells a normal, FIPS-validated or Ksplice package version apart, as trivy-db's
// oracle-oval.PackageFlavor does; Oracle advisories only apply to packages of their own flavor.
func oraclePackageFlavor(version string) string {
	version = strings.ToLower(version)
	if strings.HasSuffix(version, "_fips") {
		return "fips"
	}
	for _, sub := range strings.Split(version, ".") {
		if strings.HasPrefix(sub, "ksplice") {
			return "ksplice"
		}
	}
	return "normal"
}

// redHatAdvisory is the shape trivy-db stores Red Hat advisories in (redhat-oval.Advisory): one entry per set of
// affected platforms, with the affected CPEs stored as indices and the status as an integer.
type redHatAdvisory struct {
	Entries []*redHatEntry `json:"Entries"`
}

type redHatEntry struct {
	FixedVersion string       `json:"FixedVersion"`
	Cves         []*redHatCve `json:"Cves"`
	Arches       []string     `json:"Arches"`
	Status       int          `json:"Status"`
	Affected     []int        `json:"Affected"`
}

type redHatCve struct {
	Id       string           `json:"ID"`
	Severity dbTypes.Severity `json:"Severity"`
}

func hasIntersection(a, b []int) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// getArchAdvisories reads advisories stored per architecture (types.Advisories with entries), as trivy-db's Rocky and
// Oracle sources do, keeping the entries for the package's architecture. Advisories written before the per-arch
// format carry a single fixed version and apply to every architecture.
func (s *Scanner) getArchAdvisories(bucketName, pkgName, arch string) ([]dbTypes.Advisory, error) {
	rawAdvisories, err := s.dbc.ForEachAdvisory([]string{bucketName}, pkgName)
	if err != nil {
		return nil, fmt.Errorf("for each advisory (%s): %w", bucketName, err)
	}

	var advisories []dbTypes.Advisory
	for vulnerabilityId, value := range rawAdvisories {
		var stored dbTypes.Advisories
		if err := json.Unmarshal(value.Content, &stored); err != nil {
			return nil, fmt.Errorf("json unmarshal (advisories, %s): %w", vulnerabilityId, err)
		}

		if len(stored.Entries) == 0 {
			advisories = append(advisories, dbTypes.Advisory{
				VulnerabilityID: vulnerabilityId,
				FixedVersion:    stored.FixedVersion,
				DataSource:      &value.Source,
				Custom:          stored.Custom,
			})
			continue
		}

		for _, entry := range stored.Entries {
			if !slices.Contains(entry.Arches, arch) {
				continue
			}
			entry.VulnerabilityID = vulnerabilityId
			entry.DataSource = &value.Source
			advisories = append(advisories, entry)
		}
	}
	return advisories, nil
}

// detectOsVulnerabilities looks a package up in the advisories of its distribution release and reports the advisories
// whose fixed version the installed version has not reached (or that have no fix, where the distribution publishes
// unfixed advisories).
func (s *Scanner) detectOsVulnerabilities(p *sbomPackage.Package, info *osInfo) ([]*sbomScanningFinding.Finding, error) {
	qualifiers := p.Purl.Qualifiers.Map()
	arch := qualifiers["arch"]
	modularityLabel := qualifiers["modularitylabel"]

	// The PURL name is the canonical package name; the SBOM component name may carry a display variant.
	name := p.Purl.Name
	srcName := p.SrcName
	if srcName == "" {
		srcName = name
	}
	srcVersion := p.SrcVersion
	if srcVersion == "" {
		srcVersion = p.Version
	}

	var advisories []dbTypes.Advisory
	var err error
	// The distribution decides how versions compare, whether the advisories are keyed by binary or source package,
	// which version they are compared against, and whether advisories without a fix count.
	var lessThan func(installed, fixed string) (bool, error)
	lookupName, compared := name, p.Version
	var reportUnfixed bool

	switch info.family {
	case osFamilyAlpine:
		if info.version == "" {
			return nil, nil
		}
		lookupName, compared, lessThan, reportUnfixed = srcName, srcVersion, apkLessThan, true
		advisories, err = s.dbc.GetAdvisories(bucket.NewAlpine(minorVersion(info.version)).Name(), lookupName)
	case osFamilyWolfi:
		// Wolfi and Chainguard advisories are keyed by origin package but compared against the binary version.
		lookupName, lessThan = srcName, apkLessThan
		advisories, err = s.dbc.GetAdvisories(bucket.NewWolfi("").Name(), lookupName)
	case osFamilyChainguard:
		lookupName, lessThan = srcName, apkLessThan
		advisories, err = s.dbc.GetAdvisories(bucket.NewChainguard("").Name(), lookupName)
	case osFamilyDebian:
		if info.version == "" {
			return nil, nil
		}
		lookupName, compared, lessThan, reportUnfixed = srcName, srcVersion, debLessThan, true
		advisories, err = s.dbc.GetAdvisories(bucket.NewDebian(majorVersion(info.version)).Name(), lookupName)
	case osFamilyUbuntu:
		if info.version == "" {
			return nil, nil
		}
		lookupName, compared, lessThan, reportUnfixed = srcName, srcVersion, debLessThan, true
		advisories, err = s.dbc.GetAdvisories(bucket.NewUbuntu(info.version).Name(), lookupName)
	case osFamilyAmazon:
		if info.version == "" {
			return nil, nil
		}
		// Trivy compares Amazon Linux versions with its Debian comparer, a historical quirk; these are RPMs.
		lessThan = rpmLessThan
		advisories, err = s.dbc.GetAdvisories(bucket.NewAmazon(amazonRelease(info.version)).Name(), lookupName)
	case osFamilyPhoton:
		if info.version == "" {
			return nil, nil
		}
		lookupName, lessThan = srcName, rpmLessThan
		advisories, err = s.dbc.GetAdvisories(bucket.NewPhoton(info.version).Name(), lookupName)
	case osFamilySles:
		if info.version == "" {
			return nil, nil
		}
		lessThan = rpmLessThan
		advisories, err = s.dbc.GetAdvisories(bucket.NewSUSELinuxEnterprise(info.version).Name(), lookupName)
	case osFamilySleMicro:
		if info.version == "" {
			return nil, nil
		}
		lessThan = rpmLessThan
		advisories, err = s.dbc.GetAdvisories(bucket.NewSUSELinuxEnterpriseMicro(info.version).Name(), lookupName)
	case osFamilyOpenSuseLeap:
		if info.version == "" {
			return nil, nil
		}
		lessThan = rpmLessThan
		advisories, err = s.dbc.GetAdvisories(bucket.NewOpenSUSE(info.version).Name(), lookupName)
	case osFamilyOpenSuseTumbleweed:
		lessThan = rpmLessThan
		advisories, err = s.dbc.GetAdvisories(bucket.NewOpenSUSETumbleweed().Name(), lookupName)
	case osFamilyAlma:
		if info.version == "" {
			return nil, nil
		}
		// AlmaLinux cannot tell which module stream a modular package without a label came from; Trivy skips those.
		if strings.Contains(rpmRelease(p.Version), ".module_el") && modularityLabel == "" {
			return nil, nil
		}
		lookupName, lessThan = addModularNamespace(name, modularityLabel), rpmLessThan
		advisories, err = s.dbc.GetAdvisories(bucket.NewAlma(majorVersion(info.version)).Name(), lookupName)
	case osFamilyRocky:
		if info.version == "" {
			return nil, nil
		}
		lookupName, lessThan = addModularNamespace(name, modularityLabel), rpmLessThan
		advisories, err = s.getArchAdvisories(bucket.NewRocky(majorVersion(info.version)).Name(), lookupName, arch)
	case osFamilyOracle:
		if info.version == "" {
			return nil, nil
		}
		lessThan = rpmLessThan
		advisories, err = s.getArchAdvisories(bucket.NewOracle(majorVersion(info.version)).Name(), lookupName, arch)
		if err == nil {
			// Only advisories of the package's own flavor (normal, ksplice, fips) apply.
			flavor := oraclePackageFlavor(rpmRelease(p.Version))
			advisories = slices.DeleteFunc(advisories, func(advisory dbTypes.Advisory) bool {
				return oraclePackageFlavor(advisory.FixedVersion) != flavor
			})
		}
	case osFamilyRedHat:
		return s.detectRedHatVulnerabilities(p, info, name, arch, modularityLabel)
	default:
		return nil, nil
	}
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("get advisories (%s %s): %w", info.family, lookupName, err), lookupName)
	}

	var findings []*sbomScanningFinding.Finding
	for _, advisory := range advisories {
		if !isOsVulnerable(compared, advisory.FixedVersion, lessThan, reportUnfixed) {
			continue
		}
		finding := newOsFinding(p, advisory)
		// Debian publishes package-specific severities ("unimportant" for one package, "low" for another); Trivy
		// keeps those over the vulnerability's general severity.
		if info.family == osFamilyDebian && advisory.Severity != dbTypes.SeverityUnknown {
			finding.Vulnerability.Severity = advisory.Severity.String()
			finding.SeveritySource = vulnerability.Debian
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

// detectRedHatVulnerabilities ports Trivy's Red Hat scanner: the Red Hat advisories are keyed by the CPEs of the
// repositories a package came from and of the image it was built into. Trivy-generated SBOMs of Red Hat-built
// images record those (content sets and image NVR); otherwise the release's default repositories stand in. One
// advisory per CVE is kept: the one with the latest fixed version.
func (s *Scanner) detectRedHatVulnerabilities(p *sbomPackage.Package, info *osInfo, name, arch, modularityLabel string) ([]*sbomScanningFinding.Finding, error) {
	release := rpmRelease(p.Version)
	for _, suffix := range redHatExcludedReleaseSuffixes {
		if strings.HasSuffix(release, suffix) {
			return nil, nil
		}
	}

	contentSets, nvr := p.ContentSets, p.Nvr
	if len(contentSets) == 0 && nvr == "" {
		var ok bool
		if contentSets, ok = redHatDefaultContentSets[majorVersion(info.version)]; !ok {
			return nil, nil
		}
	}

	var cpeIndices []int
	for _, contentSet := range contentSets {
		contentSet = redHatGenericContentSetSuffix.ReplaceAllString(contentSet, "")
		indices, err := s.dbc.RedHatRepoToCPEs(contentSet)
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("red hat repo to cpes: %w", err), contentSet)
		}
		cpeIndices = append(cpeIndices, indices...)
	}
	if nvr != "" {
		indices, err := s.dbc.RedHatNVRToCPEs(nvr)
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("red hat nvr to cpes: %w", err), nvr)
		}
		cpeIndices = append(cpeIndices, indices...)
	}
	if len(cpeIndices) == 0 {
		return nil, nil
	}

	lookupName := addModularNamespace(name, modularityLabel)
	rawAdvisories, err := s.dbc.ForEachAdvisory([]string{bucket.NewRedHat("").Name()}, lookupName)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("for each advisory (red hat): %w", err), lookupName)
	}

	uniqueAdvisories := make(map[string]dbTypes.Advisory)
	for vulnerabilityId, value := range rawAdvisories {
		var advisory redHatAdvisory
		if err := json.Unmarshal(value.Content, &advisory); err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("json unmarshal (red hat advisory): %w", err), vulnerabilityId, value.Content)
		}

		for _, entry := range advisory.Entries {
			if entry == nil || !hasIntersection(cpeIndices, entry.Affected) {
				continue
			}
			// If the advisory names arches, the package must be one of them; "noarch" packages always match.
			if len(entry.Arches) != 0 && arch != "noarch" && !slices.Contains(entry.Arches, arch) {
				continue
			}

			for _, cve := range entry.Cves {
				if cve == nil {
					continue
				}
				candidate := dbTypes.Advisory{
					VulnerabilityID: vulnerabilityId,
					Severity:        cve.Severity,
					FixedVersion:    entry.FixedVersion,
					Arches:          entry.Arches,
					Status:          dbTypes.Status(entry.Status),
					DataSource:      &value.Source,
				}
				// Advisories keyed by an RHSA resolve one or more CVEs; those are reported per CVE.
				if !strings.HasPrefix(vulnerabilityId, "CVE-") {
					candidate.VulnerabilityID = cve.Id
					candidate.VendorIDs = []string{vulnerabilityId}
				}

				if existing, ok := uniqueAdvisories[candidate.VulnerabilityID]; ok {
					if !rpm.NewVersion(existing.FixedVersion).LessThan(rpm.NewVersion(candidate.FixedVersion)) {
						continue
					}
				}
				uniqueAdvisories[candidate.VulnerabilityID] = candidate
			}
		}
	}

	var findings []*sbomScanningFinding.Finding
	for _, advisory := range uniqueAdvisories {
		if !isOsVulnerable(p.Version, advisory.FixedVersion, rpmLessThan, true) {
			continue
		}
		finding := newOsFinding(p, advisory)
		finding.Vulnerability.Severity = advisory.Severity.String()
		finding.SeveritySource = vulnerability.RedHat
		findings = append(findings, finding)
	}
	slices.SortFunc(findings, func(a, b *sbomScanningFinding.Finding) int {
		return cmp.Compare(a.Vulnerability.Id, b.Vulnerability.Id)
	})
	return findings, nil
}

// isOsVulnerable tells whether an installed version is affected by an advisory: it is when the advisory has no fix
// (for distributions that publish unfixed advisories) or when the version is below the fixed one. Versions that
// cannot be parsed are not reported, as Trivy does.
func isOsVulnerable(installed, fixed string, lessThan func(installed, fixed string) (bool, error), reportUnfixed bool) bool {
	if fixed == "" {
		return reportUnfixed
	}
	less, err := lessThan(installed, fixed)
	if err != nil {
		return false
	}
	return less
}

func newOsFinding(p *sbomPackage.Package, advisory dbTypes.Advisory) *sbomScanningFinding.Finding {
	return &sbomScanningFinding.Finding{
		Vulnerability: &schema.Vulnerability{Id: advisory.VulnerabilityID},
		Package: &schema.Package{
			Name:    p.Name,
			Version: p.Version,
		},
		FixedVersion: advisory.FixedVersion,
		Status:       advisory.Status,
		DataSource:   advisory.DataSource,
	}
}
