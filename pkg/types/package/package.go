package sbom_package

import "github.com/package-url/packageurl-go"

type Package struct {
	// Name is the package name the SBOM reports. Maven, CocoaPods and Bitnami packages use the name derived from the
	// PURL instead, since SBOM producers disagree on how to fill in the component name for those.
	Name string
	// Version is the version used for matching: the component's version for language packages and the PURL's version
	// (with the epoch qualifier applied) for OS packages.
	Version string
	Purl    *packageurl.PackageURL
	// SrcName and SrcVersion identify the source package of an OS package when the SBOM provides one; distribution
	// advisories are keyed by source package.
	SrcName    string
	SrcVersion string
	// ContentSets and Nvr are the Red Hat build info Trivy records for packages of Red Hat-built images: the
	// repositories the package came from and the image's NVR (with its arch appended), which decide the CPEs the Red
	// Hat advisories are looked up by.
	ContentSets []string
	Nvr         string
	// Scope is the CycloneDX scope of the component ("required", "optional", "excluded"): whether the package ships in
	// the artifact or only took part in producing it (a build image's package, a development dependency).
	Scope string
	// Image is the container image the package was found in, when the SBOM records it: the SBOM's subject for
	// runtime packages, a build image for those nested under a build-image component.
	Image string
	// Paths are where the package was found inside that image, when the SBOM records it.
	Paths []string
	// Layers are the diff IDs of the image layers the package was found in (the layers that last wrote the files it
	// was read from), when the SBOM records them.
	Layers []string
}
