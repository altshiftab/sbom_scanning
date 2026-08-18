package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/altshiftab/utils_go/pkg/cloud/gcp/artifact_registry"
	"github.com/altshiftab/utils_go/pkg/cloud/gcp/artifact_registry/artifact_registry_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
)

// The Trivy database is published as an OCI artifact; tag "2" is the schema this scanner reads. Its single layer is a
// gzip tarball holding trivy.db and metadata.json.
const (
	trivyDatabaseRegistry   = "https://ghcr.io"
	trivyDatabaseRepository = "aquasecurity/trivy-db"
	trivyDatabaseTag        = "2"

	databaseFileName = "trivy.db"
	metadataFileName = "metadata.json"

	// databaseStaleAfter is how old a database may get before its age is pointed out.
	databaseStaleAfter = 48 * time.Hour
)

var (
	ErrDatabaseMissing = errors.New("vulnerability database missing")
	ErrNoLayers        = errors.New("database artifact has no layers")
	ErrBlobStatus      = errors.New("unexpected status fetching the database blob")
)

// databaseMetadata is what Trivy writes beside the database.
type databaseMetadata struct {
	Version    int       `json:"Version"`
	NextUpdate time.Time `json:"NextUpdate"`
	UpdatedAt  time.Time `json:"UpdatedAt"`
}

// defaultDatabaseDir is where Trivy itself keeps the database, so an existing one is reused.
func defaultDatabaseDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(".", "trivy-db")
	}
	return filepath.Join(cacheDir, "trivy", "db")
}

// databaseAge tells how old the database in dir is, from its metadata; zero when unknown.
func databaseAge(dir string, now time.Time) time.Duration {
	data, err := os.ReadFile(filepath.Join(dir, metadataFileName)) //nolint:gosec // G304: the database directory is the user's choice
	if err != nil {
		return 0
	}
	var metadata databaseMetadata
	if err := json.Unmarshal(data, &metadata); err != nil || metadata.UpdatedAt.IsZero() {
		return 0
	}
	return now.Sub(metadata.UpdatedAt)
}

// downloadDatabase fetches the latest Trivy database from the registry into dir, replacing what is there. The
// registry is anonymous: a pull token is requested first, then the artifact's manifest and its layer are read the
// OCI way. Progress notes go to the given writer.
func downloadDatabase(ctx context.Context, registry *url.URL, dir string, progress io.Writer) error {
	if registry == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("registry"))
	}
	if dir == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("dir"))
	}

	tokenUrl := *registry
	tokenUrl.Path = "/token"
	tokenUrl.RawQuery = url.Values{"scope": {"repository:" + trivyDatabaseRepository + ":pull"}}.Encode()
	// FetchJson reads and closes the response body itself; the response is only returned for its headers.
	_, tokenResponse, err := altshiftHttpUtils.FetchJson[*struct {
		Token string `json:"token"`
	}](ctx, tokenUrl.String()) //nolint:bodyclose // the body is consumed and closed by FetchJson
	if err != nil {
		return altshiftErrors.New(fmt.Errorf("fetch json (token): %w", err), tokenUrl.String())
	}
	if tokenResponse == nil || tokenResponse.Token == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("token"), tokenUrl.String())
	}
	authorization := fetch_config.WithHeaders(map[string]string{"Authorization": "Bearer " + tokenResponse.Token})

	client := artifact_registry.NewClient("", artifact_registry_config.WithBaseUrl(registry))
	_, manifest, err := client.GetManifest(ctx, trivyDatabaseRepository, trivyDatabaseTag, authorization)
	if err != nil {
		return fmt.Errorf("get manifest: %w", err)
	}
	if manifest == nil || len(manifest.Layers) == 0 || manifest.Layers[0] == nil {
		return altshiftErrors.NewWithTrace(ErrNoLayers)
	}
	digest := manifest.Layers[0].Digest

	blobUrl := *registry
	blobUrl.Path = "/v2/" + trivyDatabaseRepository + "/blobs/" + digest
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, blobUrl.String(), nil)
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("new request: %w", err), blobUrl.String())
	}
	request.Header.Set("Authorization", "Bearer "+tokenResponse.Token)
	// The blob is around a gigabyte, so it is streamed rather than fetched into memory.
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("get blob: %w", err), blobUrl.String())
	}
	if response == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("response"), blobUrl.String())
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return altshiftErrors.NewWithTrace(fmt.Errorf("%w: %d", ErrBlobStatus, response.StatusCode), blobUrl.String(), response.StatusCode)
	}
	fmt.Fprintf(progress, "downloading the vulnerability database (%s, %.0f MiB)...\n", digest, float64(manifest.Layers[0].Size)/(1<<20))

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("mkdir all: %w", err), dir)
	}
	return extractDatabase(response.Body, dir)
}

// extractDatabase reads the database tarball into dir, replacing the files there only once each is complete.
func extractDatabase(reader io.Reader, dir string) error {
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("gzip new reader: %w", err))
	}
	defer func() { _ = gzipReader.Close() }()

	var written []string
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return altshiftErrors.NewWithTrace(fmt.Errorf("tar next: %w", err))
		}
		name := filepath.Base(header.Name)
		if header.Typeflag != tar.TypeReg || (name != databaseFileName && name != metadataFileName) {
			continue
		}

		file, err := os.CreateTemp(dir, name+".*")
		if err != nil {
			return altshiftErrors.NewWithTrace(fmt.Errorf("create temp: %w", err), dir)
		}
		if _, err := io.Copy(file, tarReader); err != nil { //nolint:gosec // G110: the archive is the trusted database publication, and it goes to disk, not memory
			_ = file.Close()
			_ = os.Remove(file.Name())
			return altshiftErrors.NewWithTrace(fmt.Errorf("copy %s: %w", name, err), name)
		}
		if err := file.Close(); err != nil {
			_ = os.Remove(file.Name())
			return altshiftErrors.NewWithTrace(fmt.Errorf("close %s: %w", name, err), name)
		}
		if err := os.Rename(file.Name(), filepath.Join(dir, name)); err != nil {
			_ = os.Remove(file.Name())
			return altshiftErrors.NewWithTrace(fmt.Errorf("rename %s: %w", name, err), name)
		}
		written = append(written, name)
	}

	for _, name := range []string{databaseFileName, metadataFileName} {
		var found bool
		for _, w := range written {
			found = found || w == name
		}
		if !found {
			return altshiftErrors.NewWithTrace(fmt.Errorf("%w: %s not in the artifact", ErrDatabaseMissing, name), written)
		}
	}
	return nil
}
