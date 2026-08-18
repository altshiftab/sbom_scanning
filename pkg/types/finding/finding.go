package finding

import (
	"time"

	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type Finding struct {
	Vulnerability *schema.Vulnerability `json:"vulnerability,omitzero"`
	// Package carries the SBOM's scope for the package as its install scope ("required", "optional", "excluded")
	// and where it was found as its path, when the SBOM records them.
	Package *schema.Package `json:"package,omitzero"`
	// Container is the image the package was found in, when the SBOM records it: the SBOM's subject for packages
	// that ship, a build image for packages that only took part in producing it.
	Container *schema.Container `json:"container,omitzero"`
	// Layer is the diff ID of the image layer that introduced (last wrote) the package, when the SBOM records it.
	Layer            string            `json:"layer,omitzero"`
	FixedVersion     string            `json:"fixed_version,omitzero"`
	SeveritySource   types.SourceID    `json:"severity_source,omitzero"`
	Status           types.Status      `json:"status,omitzero"`
	DataSource       *types.DataSource `json:"data_source,omitzero"`
	Title            string            `json:"title,omitzero"`
	CweIDs           []string          `json:"cwe_ids,omitzero"`
	References       []string          `json:"references,omitzero"`
	PublishedDate    *time.Time        `json:"published_date,omitzero"`
	LastModifiedDate *time.Time        `json:"last_modified_date,omitzero"`
}
