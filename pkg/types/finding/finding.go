package finding

import (
	"time"

	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type Finding struct {
	Vulnerability    *schema.Vulnerability `json:"vulnerability,omitzero"`
	Package          *schema.Package       `json:"package,omitzero"`
	FixedVersion     string                `json:"fixed_version,omitzero"`
	SeveritySource   types.SourceID        `json:"severity_source,omitzero"`
	Status           types.Status          `json:"status,omitzero"`
	DataSource       *types.DataSource     `json:"data_source,omitzero"`
	Title            string                `json:"title,omitzero"`
	CweIDs           []string              `json:"cwe_ids,omitzero"`
	References       []string              `json:"references,omitzero"`
	PublishedDate    *time.Time            `json:"published_date,omitzero"`
	LastModifiedDate *time.Time            `json:"last_modified_date,omitzero"`
}
