package memory_artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"io"

	"github.com/Motmedel/utils_go/pkg/errors"
	errors2 "github.com/altshiftab/sbom_scanning/pkg/errors"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/opencontainers/go-digest"
	"github.com/samber/lo"
)

// Artifact implements fartifact.Artifact for in-memory SBOM data.
type Artifact struct {
	Name   string
	Data   []byte
	Cache  cache.ArtifactCache
	Option artifact.Option

	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager
}

func (a *Artifact) Inspect(ctx context.Context) (artifact.Reference, error) {
	r := bytes.NewReader(a.Data)

	format, err := sbom.DetectFormat(r)
	if err != nil {
		return artifact.Reference{}, errors.NewWithTrace(fmt.Errorf("trivy sbom detect format: %w", err))
	}

	if format == sbom.FormatUnknown {
		return artifact.Reference{}, errors.NewWithTrace(errors2.ErrUnknownSbomFormat)
	}

	// Rewind after format detection
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return artifact.Reference{}, errors.NewWithTrace(fmt.Errorf("reader seek: %w", err))
	}

	bom, err := sbom.Decode(ctx, r, format)
	if err != nil {
		return artifact.Reference{}, errors.NewWithTrace(fmt.Errorf("trivy sbom decode: %w", err), format)
	}

	blobInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		OS:            lo.FromPtr(bom.Metadata.OS),
		PackageInfos:  bom.Packages,
		Applications:  bom.Applications,
	}

	cacheKey, err := a.calcCacheKey(blobInfo)
	if err != nil {
		return artifact.Reference{}, errors.New(fmt.Errorf("calc Cache key: %w", err), blobInfo)
	}

	if err = a.Cache.PutBlob(ctx, cacheKey, blobInfo); err != nil {
		return artifact.Reference{}, errors.New(fmt.Errorf("put blob: %w", err), cacheKey, blobInfo)
	}

	var artifactType types.ArtifactType
	switch format {
	case sbom.FormatCycloneDXJSON, sbom.FormatCycloneDXXML, sbom.FormatAttestCycloneDXJSON,
		sbom.FormatLegacyCosignAttestCycloneDXJSON, sbom.FormatSigstoreBundleCycloneDXJSON:
		artifactType = types.TypeCycloneDX
	case sbom.FormatSPDXTV, sbom.FormatSPDXJSON, sbom.FormatAttestSPDXJSON, sbom.FormatSigstoreBundleSPDXJSON:
		artifactType = types.TypeSPDX
	}

	return artifact.Reference{
		Name:    a.Name,
		Type:    artifactType,
		ID:      cacheKey,
		BlobIDs: []string{cacheKey},
		ImageMetadata: artifact.ImageMetadata{
			ID:          bom.Metadata.ImageID,
			DiffIDs:     bom.Metadata.DiffIDs,
			RepoTags:    bom.Metadata.RepoTags,
			RepoDigests: bom.Metadata.RepoDigests,
			Reference:   bom.Metadata.Reference,
		},
		BOM: bom.BOM,
	}, nil
}

func (a *Artifact) Clean(ref artifact.Reference) error {
	return a.Cache.DeleteBlobs(context.TODO(), ref.BlobIDs)
}

func (a *Artifact) calcCacheKey(blobInfo types.BlobInfo) (string, error) {
	h := sha256.New()
	if err := json.MarshalWrite(h, blobInfo); err != nil {
		return "", errors.NewWithTrace(fmt.Errorf("json marshal write: %w", err))
	}

	d := digest.NewDigest(digest.SHA256, h)
	cacheKey, err := cache.CalcKey(d.String(), 0, a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.Option)
	if err != nil {
		return "", errors.NewWithTrace(fmt.Errorf("trivy Cache calc key: %w", err))
	}

	return cacheKey, nil
}
