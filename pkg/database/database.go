// Package database fetches the Trivy vulnerability database the scanner reads, and reads what Trivy records about it.
package database

import (
	"archive/tar"
	"cmp"
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
	"slices"
	"strings"
	"time"

	"github.com/altshiftab/utils_go/pkg/cloud/gcp/artifact_registry"
	"github.com/altshiftab/utils_go/pkg/cloud/gcp/artifact_registry/artifact_registry_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
)

const (
	// FileName is the database itself, a bbolt file.
	FileName = "trivy.db"
	// MetadataFileName is the file Trivy writes beside the database, saying when it was built.
	MetadataFileName = "metadata.json"
	// Tag names the database schema the scanner reads. The artifact under it has a single layer, a gzip tarball
	// holding FileName and MetadataFileName.
	Tag = "2"

	httpsScheme = "https"
)

var (
	ErrDatabaseMissing = errors.New("vulnerability database missing")
	ErrNoLayers        = errors.New("database artifact has no layers")
	ErrBlobStatus      = errors.New("unexpected status fetching the database blob")
	ErrChallenge       = errors.New("unsupported registry authentication challenge")
	ErrManifestStatus  = errors.New("unexpected status fetching the database manifest")
	ErrStalled         = errors.New("database download stalled")
)

// timeouts bound the download. Each request but the blob's must be answered within request; the blob, over a hundred
// megabytes, may take as long as it takes while it keeps coming, and is given up for the next source after stall
// without a byte. A variable rather than constants, so the tests need not wait minutes.
var timeouts = struct {
	request time.Duration
	stall   time.Duration
}{request: 30 * time.Second, stall: time.Minute}

// Source is a registry repository the database is published under.
type Source struct {
	Registry   *url.URL
	Repository string
}

func (source *Source) String() string {
	if source == nil {
		return ""
	}
	if source.Registry == nil {
		return source.Repository
	}
	return source.Registry.Host + "/" + source.Repository
}

// DefaultSources are where the database is published: ghcr.io, where Aqua publishes it, and then mirror.gcr.io,
// Google's mirror of the Docker Hub copy, which trails by some hours but does not rate-limit anonymous pulls the way
// ghcr.io can.
func DefaultSources() []*Source {
	return []*Source{
		{Registry: &url.URL{Scheme: httpsScheme, Host: "ghcr.io"}, Repository: "aquasecurity/trivy-db"},
		{Registry: &url.URL{Scheme: httpsScheme, Host: "mirror.gcr.io"}, Repository: "aquasec/trivy-db"},
	}
}

// Metadata is what Trivy records beside the database.
type Metadata struct {
	Version    int       `json:"Version"`
	NextUpdate time.Time `json:"NextUpdate"`
	UpdatedAt  time.Time `json:"UpdatedAt"`
}

// ReadMetadata reads the metadata of the database in dir.
func ReadMetadata(dir string) (*Metadata, error) {
	path := filepath.Join(dir, MetadataFileName)
	data, err := os.ReadFile(path) //nolint:gosec // G304: the database directory is the caller's choice
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("read file: %w", err), path)
	}
	var metadata Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: json unmarshal: %w", altshiftErrors.ErrParseError, err), path)
	}
	if metadata.UpdatedAt.IsZero() {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("updated at")), path)
	}
	return &metadata, nil
}

// Download fetches the database into dir from the first of the sources that serves it, replacing what is there; the
// errors of the sources tried are returned together when none does. Progress notes go to progress, when given.
func Download(ctx context.Context, dir string, sources []*Source, progress io.Writer) error {
	if dir == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("dir"))
	}
	if len(sources) == 0 {
		return altshiftErrors.NewWithTrace(empty_error.New("sources"))
	}
	if progress == nil {
		progress = io.Discard
	}

	var errs []error
	for _, source := range sources {
		err := download(ctx, dir, source, progress)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return err
		}
		errs = append(errs, fmt.Errorf("%s: %w", source, err))
		fmt.Fprintf(progress, "could not download the vulnerability database from %s: %v\n", source, err)
	}
	return errors.Join(errs...)
}

// download fetches the database from one source. The registry is read the OCI way, anonymously: the manifest is asked
// for, a pull token is fetched when the registry challenges for one, and the manifest's layer is streamed to disk.
func download(ctx context.Context, dir string, source *Source, progress io.Writer) error {
	if source == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("source"))
	}
	if source.Registry == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("source registry"))
	}
	if source.Repository == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("source repository"))
	}

	requestClient := &http.Client{Timeout: timeouts.request}
	token, err := pullToken(ctx, source, requestClient)
	if err != nil {
		return fmt.Errorf("pull token: %w", err)
	}
	options := []fetch_config.Option{fetch_config.WithHttpClient(requestClient)}
	if token != "" {
		options = append(options, fetch_config.WithHeaders(map[string]string{"Authorization": "Bearer " + token}))
	}

	client := artifact_registry.NewClient("", artifact_registry_config.WithBaseUrl(source.Registry))
	_, manifest, err := client.GetManifest(ctx, source.Repository, Tag, options...)
	if err != nil {
		return fmt.Errorf("get manifest: %w", err)
	}
	if manifest == nil || len(manifest.Layers) == 0 || manifest.Layers[0] == nil {
		return altshiftErrors.NewWithTrace(ErrNoLayers, source)
	}
	layer := manifest.Layers[0]

	// A watchdog cancels the blob's request when no byte has come for the stall timeout, the wait for the response
	// included.
	blobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	watchdog := time.AfterFunc(timeouts.stall, cancel)
	defer watchdog.Stop()
	stalled := func(err error) error {
		if blobCtx.Err() != nil && ctx.Err() == nil {
			return fmt.Errorf("%w: nothing for %s: %w", ErrStalled, timeouts.stall, err)
		}
		return err
	}

	blobUrl := *source.Registry
	blobUrl.Path = "/v2/" + source.Repository + "/blobs/" + layer.Digest
	request, err := http.NewRequestWithContext(blobCtx, http.MethodGet, blobUrl.String(), nil)
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("new request: %w", err), blobUrl.String())
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	// The blob is over a hundred megabytes, and well over a gigabyte unpacked, so it is streamed rather than fetched
	// into memory.
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return altshiftErrors.NewWithTrace(stalled(fmt.Errorf("get blob: %w", err)), blobUrl.String())
	}
	if response == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("response"), blobUrl.String())
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return altshiftErrors.NewWithTrace(fmt.Errorf("%w: %d", ErrBlobStatus, response.StatusCode), blobUrl.String(), response.StatusCode)
	}
	fmt.Fprintf(progress, "downloading the vulnerability database from %s (%s, %.0f MiB)...\n", source, layer.Digest, float64(layer.Size)/(1<<20))

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("mkdir all: %w", err), dir)
	}
	if err := extract(&watchedReader{reader: response.Body, watchdog: watchdog, timeout: timeouts.stall}, dir); err != nil {
		return stalled(err)
	}
	return nil
}

// watchedReader puts its watchdog back each time bytes come.
type watchedReader struct {
	reader   io.Reader
	watchdog *time.Timer
	timeout  time.Duration
}

func (r *watchedReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.watchdog.Reset(r.timeout)
	}
	return n, err //nolint:wrapcheck // a reader passes its source's errors on as they are, io.EOF above all
}

// pullToken asks for the database manifest without credentials. A registry that serves it anonymously needs no token
// (mirror.gcr.io); one that answers with a Bearer challenge (ghcr.io) is asked for an anonymous token at the realm the
// challenge names.
func pullToken(ctx context.Context, source *Source, client *http.Client) (string, error) {
	manifestUrl := *source.Registry
	manifestUrl.Path = "/v2/" + source.Repository + "/manifests/" + Tag
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, manifestUrl.String(), nil)
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("new request: %w", err), manifestUrl.String())
	}
	request.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json")
	response, err := client.Do(request)
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("head manifest: %w", err), manifestUrl.String())
	}
	if response == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("response"), manifestUrl.String())
	}
	_ = response.Body.Close()

	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		return "", nil
	case response.StatusCode != http.StatusUnauthorized:
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("%w: %d", ErrManifestStatus, response.StatusCode), manifestUrl.String())
	}

	challenge := response.Header.Get("WWW-Authenticate")
	params, ok := parseBearerChallenge(challenge)
	if !ok || params["realm"] == "" {
		return "", altshiftErrors.NewWithTrace(ErrChallenge, challenge)
	}
	tokenUrl, err := url.Parse(params["realm"])
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("%w: url parse (realm): %w", altshiftErrors.ErrParseError, err), challenge)
	}
	if tokenUrl.Scheme != httpsScheme && tokenUrl.Scheme != source.Registry.Scheme {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("%w: realm scheme %q", ErrChallenge, tokenUrl.Scheme), challenge)
	}
	query := tokenUrl.Query()
	if service := params["service"]; service != "" {
		query.Set("service", service)
	}
	query.Set("scope", cmp.Or(params["scope"], "repository:"+source.Repository+":pull"))
	tokenUrl.RawQuery = query.Encode()

	// Registries answer with "token", some with "access_token" as well or instead.
	// FetchJson reads and closes the response body itself.
	_, tokenResponse, err := altshiftHttpUtils.FetchJson[*struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}](ctx, tokenUrl.String(), fetch_config.WithHttpClient(client)) //nolint:bodyclose // the body is consumed and closed by FetchJson
	if err != nil {
		return "", altshiftErrors.New(fmt.Errorf("fetch json (token): %w", err), tokenUrl.String())
	}
	if tokenResponse == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("token response"), tokenUrl.String())
	}
	token := cmp.Or(tokenResponse.Token, tokenResponse.AccessToken)
	if token == "" {
		return "", altshiftErrors.NewWithTrace(empty_error.New("token"), tokenUrl.String())
	}
	return token, nil
}

// parseBearerChallenge reads the parameters of a Bearer challenge (RFC 6750, as registries send it:
// `Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:x:pull"`). Parameter names are
// case-insensitive and returned lowercased.
func parseBearerChallenge(header string) (map[string]string, bool) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(header), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return nil, false
	}

	params := make(map[string]string)
	for {
		rest = strings.TrimLeft(rest, " \t,")
		if rest == "" {
			return params, true
		}
		name, after, found := strings.Cut(rest, "=")
		if !found {
			return nil, false
		}
		name = strings.ToLower(strings.TrimSpace(name))
		after = strings.TrimLeft(after, " \t")

		var value string
		if strings.HasPrefix(after, `"`) {
			var builder strings.Builder
			i := 1
			for ; i < len(after); i++ {
				c := after[i]
				if c == '\\' && i+1 < len(after) {
					i++
					builder.WriteByte(after[i])
					continue
				}
				if c == '"' {
					break
				}
				builder.WriteByte(c)
			}
			if i >= len(after) {
				return nil, false
			}
			value = builder.String()
			rest = after[i+1:]
		} else {
			end := strings.IndexByte(after, ',')
			if end == -1 {
				end = len(after)
			}
			value = strings.TrimSpace(after[:end])
			rest = after[end:]
		}
		if name == "" {
			return nil, false
		}
		params[name] = value
	}
}

// extract reads the database tarball into dir, replacing each file there only once its new copy is complete.
func extract(reader io.Reader, dir string) error {
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
		if header.Typeflag != tar.TypeReg || (name != FileName && name != MetadataFileName) {
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

	for _, name := range []string{FileName, MetadataFileName} {
		if !slices.Contains(written, name) {
			return altshiftErrors.NewWithTrace(fmt.Errorf("%w: %s not in the artifact", ErrDatabaseMissing, name), written)
		}
	}
	return nil
}
