package finding

import (
	"time"

	"github.com/Motmedel/utils_go/pkg/schema"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type Finding struct {
	Vulnerability    *schema.Vulnerability `json:"vulnerability,omitempty"`
	Package          *schema.Package       `json:"package,omitempty"`
	FixedVersion     string                `json:"fixed_version,omitempty"`
	SeveritySource   types.SourceID        `json:"severity_source,omitempty"`
	Status           types.Status          `json:"status,omitempty"`
	DataSource       *types.DataSource     `json:"data_source,omitempty"`
	Title            string                `json:"title,omitempty"`
	CweIDs           []string              `json:"cwe_ids,omitempty"`
	References       []string              `json:"references,omitempty"`
	PublishedDate    *time.Time            `json:"published_date,omitempty"`
	LastModifiedDate *time.Time            `json:"last_modified_date,omitempty"`
}
