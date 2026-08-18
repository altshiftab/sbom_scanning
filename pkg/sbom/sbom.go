package sbom

import (
	"bytes"
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	sbomScanningErrors "github.com/altshiftab/sbom_scanning/pkg/errors"
	sbomPackage "github.com/altshiftab/sbom_scanning/pkg/types/package"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/package-url/packageurl-go"
)

// Trivy records the source package of an OS package, and the Red Hat build info of packages from Red Hat-built
// images, in these CycloneDX component properties.
const (
	trivyPropertyPrefix = "aquasecurity:trivy:"
	propertySrcName     = trivyPropertyPrefix + "SrcName"
	propertySrcVersion  = trivyPropertyPrefix + "SrcVersion"
	propertySrcRelease  = trivyPropertyPrefix + "SrcRelease"
	propertySrcEpoch    = trivyPropertyPrefix + "SrcEpoch"
	propertyContentSet  = trivyPropertyPrefix + "ContentSet"
	propertyNvr         = trivyPropertyPrefix + "NVR"
	propertyArch        = trivyPropertyPrefix + "Arch"
)

// spdxSourcePackagePrefix starts the SPDX sourceInfo Trivy writes for OS packages: "built package from: <name> <version>".
const spdxSourcePackagePrefix = "built package from: "

// The SBOM formats are only read for the handful of fields the scanner needs, so the decoders below cover the
// component/package shape rather than the full CycloneDX and SPDX schemas.

type cycloneDxProperty struct {
	Name  string `json:"name" xml:"name,attr"`
	Value string `json:"value" xml:",chardata"`
}

type cycloneDxComponent struct {
	Group      string                `json:"group" xml:"group"`
	Name       string                `json:"name" xml:"name"`
	Version    string                `json:"version" xml:"version"`
	Purl       string                `json:"purl" xml:"purl"`
	Properties []*cycloneDxProperty  `json:"properties" xml:"properties>property"`
	Components []*cycloneDxComponent `json:"components" xml:"components>component"`
}

type cycloneDxMetadata struct {
	Component *cycloneDxComponent `json:"component" xml:"component"`
}

type cycloneDxBom struct {
	XMLName    xml.Name              `json:"-" xml:"bom"`
	BomFormat  string                `json:"bomFormat" xml:"-"`
	Metadata   *cycloneDxMetadata    `json:"metadata" xml:"metadata"`
	Components []*cycloneDxComponent `json:"components" xml:"components>component"`
}

type spdxExternalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type spdxPackage struct {
	Name         string             `json:"name"`
	Version      string             `json:"versionInfo"`
	SourceInfo   string             `json:"sourceInfo"`
	ExternalRefs []*spdxExternalRef `json:"externalRefs"`
}

type spdxDocument struct {
	SpdxVersion string         `json:"spdxVersion"`
	Packages    []*spdxPackage `json:"packages"`
}

// jsonOptions keep the decoders tolerant of third-party SBOMs, matching what encoding/json v1 accepted.
var jsonOptions = json.JoinOptions(
	json.MatchCaseInsensitiveNames(true),
	jsontext.AllowDuplicateNames(true),
	jsontext.AllowInvalidUTF8(true),
)

// Parse extracts the packages of a CycloneDX (JSON or XML) or SPDX (JSON) SBOM. Components without a parsable PURL are
// skipped, since the PURL is what identifies the ecosystem and package to look up. Failures to make sense of the input
// wrap altshiftErrors.ErrParseError.
func Parse(data []byte) ([]*sbomPackage.Package, error) {
	data = bytes.TrimLeft(data, " \t\r\n")
	if len(data) == 0 {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %w", altshiftErrors.ErrParseError, empty_error.New("data (trimmed)")))
	}

	switch data[0] {
	case '{':
		var probe struct {
			BomFormat   string `json:"bomFormat"`
			SpdxVersion string `json:"spdxVersion"`
		}
		if err := json.Unmarshal(data, &probe, jsonOptions); err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: json unmarshal (probe): %w", altshiftErrors.ErrParseError, err))
		}
		switch {
		case probe.BomFormat == "CycloneDX":
			return parseCycloneDxJson(data)
		case probe.SpdxVersion != "":
			return parseSpdxJson(data)
		}
	case '<':
		return parseCycloneDxXml(data)
	}

	return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %w", altshiftErrors.ErrParseError, sbomScanningErrors.ErrUnexpectedSbomFormat))
}

func parseCycloneDxJson(data []byte) ([]*sbomPackage.Package, error) {
	var bom cycloneDxBom
	if err := json.Unmarshal(data, &bom, jsonOptions); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: json unmarshal (cyclonedx): %w", altshiftErrors.ErrParseError, err))
	}
	return cycloneDxPackages(&bom), nil
}

func parseCycloneDxXml(data []byte) ([]*sbomPackage.Package, error) {
	var bom cycloneDxBom
	if err := xml.Unmarshal(data, &bom); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: xml unmarshal (cyclonedx): %w", altshiftErrors.ErrParseError, err))
	}
	return cycloneDxPackages(&bom), nil
}

func cycloneDxPackages(bom *cycloneDxBom) []*sbomPackage.Package {
	var packages []*sbomPackage.Package

	var walk func(components []*cycloneDxComponent)
	walk = func(components []*cycloneDxComponent) {
		for _, component := range components {
			if component == nil {
				continue
			}
			if p := cycloneDxPackage(component); p != nil {
				packages = append(packages, p)
			}
			// Components may nest their own components (e.g. the modules of an application).
			walk(component.Components)
		}
	}

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		walk([]*cycloneDxComponent{bom.Metadata.Component})
	}
	walk(bom.Components)

	return packages
}

func cycloneDxPackage(component *cycloneDxComponent) *sbomPackage.Package {
	purl, ok := parsePurl(component.Purl)
	if !ok {
		return nil
	}

	p := newPackage(component.Name, component.Group, component.Version, purl)
	if p == nil {
		return nil
	}

	if isOsPurl(purl) {
		var srcEpoch, srcVersion, srcRelease, nvr, arch string
		for _, property := range component.Properties {
			if property == nil {
				continue
			}
			switch property.Name {
			case propertySrcName:
				p.SrcName = property.Value
			case propertySrcVersion:
				srcVersion = property.Value
			case propertySrcRelease:
				srcRelease = property.Value
			case propertySrcEpoch:
				srcEpoch = property.Value
			case propertyContentSet:
				p.ContentSets = append(p.ContentSets, property.Value)
			case propertyNvr:
				nvr = property.Value
			case propertyArch:
				arch = property.Value
			}
		}
		if srcVersion != "" {
			p.SrcVersion = formatVersion(srcEpoch, srcVersion, srcRelease)
		}
		// Trivy keys the NVR-to-CPE lookup by "<nvr>-<arch>".
		if nvr != "" {
			p.Nvr = nvr + "-" + arch
		}
		fillSrcFromPurl(p)
	}

	return p
}

func parseSpdxJson(data []byte) ([]*sbomPackage.Package, error) {
	var document spdxDocument
	if err := json.Unmarshal(data, &document, jsonOptions); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: json unmarshal (spdx): %w", altshiftErrors.ErrParseError, err))
	}

	var packages []*sbomPackage.Package
	for _, spdxPkg := range document.Packages {
		if spdxPkg == nil {
			continue
		}

		var purl *packageurl.PackageURL
		for _, ref := range spdxPkg.ExternalRefs {
			if ref == nil || ref.Type != "purl" {
				continue
			}
			if parsed, ok := parsePurl(ref.Locator); ok {
				purl = parsed
				break
			}
		}
		if purl == nil {
			continue
		}

		p := newPackage(spdxPkg.Name, "", spdxPkg.Version, purl)
		if p == nil {
			continue
		}

		if isOsPurl(purl) {
			if source, ok := strings.CutPrefix(spdxPkg.SourceInfo, spdxSourcePackagePrefix); ok {
				p.SrcName, p.SrcVersion, _ = strings.Cut(source, " ")
			}
			fillSrcFromPurl(p)
		}

		packages = append(packages, p)
	}

	return packages, nil
}

func parsePurl(s string) (*packageurl.PackageURL, bool) {
	if s == "" {
		return nil, false
	}
	purl, err := packageurl.FromString(s)
	if err != nil {
		return nil, false
	}
	return &purl, true
}

func isOsPurl(purl *packageurl.PackageURL) bool {
	switch purl.Type {
	case packageurl.TypeApk, packageurl.TypeDebian, packageurl.TypeRPM:
		return true
	default:
		return false
	}
}

// newPackage builds a package the way Trivy reads SBOM components: the name is what the SBOM says (with the group
// prepended when present), except for ecosystems whose producers disagree on the name field; the version of an OS
// package comes from the PURL, whose epoch qualifier is folded back into it.
func newPackage(name, group, version string, purl *packageurl.PackageURL) *sbomPackage.Package {
	switch purl.Type {
	case packageurl.TypeMaven, "gradle", packageurl.TypeCocoapods, packageurl.TypeBitnami:
		name = purlName(purl)
	default:
		if name == "" {
			name = purlName(purl)
		} else if group != "" {
			name = group + "/" + name
		}
	}

	if isOsPurl(purl) {
		version = cmp.Or(purl.Version, version)
		if epoch := purl.Qualifiers.Map()["epoch"]; epoch != "" && epoch != "0" && !strings.Contains(version, ":") {
			version = epoch + ":" + version
		}
	} else {
		version = cmp.Or(version, purl.Version)
	}

	if name == "" || version == "" {
		return nil
	}

	return &sbomPackage.Package{Name: name, Version: version, Purl: purl}
}

// purlName is the package name as the PURL spells it: "namespace/name" ("namespace:name" for Maven), and
// "name/subpath" for CocoaPods, whose subpath is the submodule.
func purlName(purl *packageurl.PackageURL) string {
	if isOsPurl(purl) {
		return purl.Name
	}
	switch {
	case purl.Namespace != "" && (purl.Type == packageurl.TypeMaven || purl.Type == "gradle"):
		return purl.Namespace + ":" + purl.Name
	case purl.Namespace != "":
		return purl.Namespace + "/" + purl.Name
	case purl.Subpath != "" && purl.Type == packageurl.TypeCocoapods:
		return purl.Name + "/" + purl.Subpath
	default:
		return purl.Name
	}
}

// fillSrcFromPurl completes the source package from the "upstream" qualifier (as Syft writes it) when the SBOM's own
// fields did not provide it, and falls back to the binary package for whatever is still missing.
func fillSrcFromPurl(p *sbomPackage.Package) {
	if p.SrcName == "" {
		if upstream := p.Purl.Qualifiers.Map()["upstream"]; upstream != "" {
			p.SrcName, p.SrcVersion = parseUpstream(p.Purl.Type, upstream)
		}
	}
	if p.SrcName == "" {
		p.SrcName = p.Name
	}
	if p.SrcVersion == "" {
		p.SrcVersion = p.Version
	}
}

// parseUpstream reads Syft's "upstream" qualifier: "name", "name@version", or for RPMs the source RPM file name
// "name-version-release.src.rpm". A source RPM name that does not have that shape yields nothing, so the binary
// package stands in.
func parseUpstream(purlType, upstream string) (string, string) {
	if purlType == packageurl.TypeRPM {
		if nvr, ok := strings.CutSuffix(upstream, ".src.rpm"); ok {
			nv, release, ok := cutLast(nvr, '-')
			if !ok {
				return "", ""
			}
			name, version, ok := cutLast(nv, '-')
			if !ok {
				return "", ""
			}
			return name, version + "-" + release
		}
	}
	name, version, _ := strings.Cut(upstream, "@")
	return name, version
}

func cutLast(s string, sep byte) (string, string, bool) {
	i := strings.LastIndexByte(s, sep)
	if i == -1 {
		return s, "", false
	}
	return s[:i], s[i+1:], true
}

func formatVersion(epoch, version, release string) string {
	v := version
	if release != "" {
		v += "-" + release
	}
	if epoch != "" {
		if e, err := strconv.Atoi(epoch); err == nil && e != 0 {
			v = epoch + ":" + v
		}
	}
	return v
}
