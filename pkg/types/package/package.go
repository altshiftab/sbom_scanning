package sbom_package

import "github.com/package-url/packageurl-go"

type Package struct {
	Name    string
	Version string
	Purl    *packageurl.PackageURL
}
