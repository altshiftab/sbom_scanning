package database

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

const testDigest = "sha256:0123456789abcdef"

// archive gzips a tarball of the given files, as the database is published.
func archive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, name := range []string{FileName, MetadataFileName, "README"} {
		data, ok := files[name]
		if !ok {
			continue
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tarWriter.Write([]byte(data)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buffer.Bytes()
}

// registry describes how a test registry behaves.
type registry struct {
	// challenge makes the registry demand a token the way ghcr.io does; without it the registry serves anonymously,
	// the way mirror.gcr.io does.
	challenge bool
	// manifestStatus, when set, is returned for every manifest request.
	manifestStatus int
	// blobStatus, when set, is returned for the blob.
	blobStatus int
	archive    []byte
}

// newRegistry serves the database artifact under repository and returns the source naming it, and a counter of the
// blob downloads it served.
func newRegistry(t *testing.T, repository string, behaviour *registry) (*Source, *atomic.Int32) {
	t.Helper()
	var blobs atomic.Int32
	const token = "anonymous-token"
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized := !behaviour.challenge || r.Header.Get("Authorization") == "Bearer "+token
		switch r.URL.Path {
		case "/token":
			if !behaviour.challenge {
				http.NotFound(w, r)
				return
			}
			if r.URL.Query().Get("scope") != "repository:"+repository+":pull" || r.URL.Query().Get("service") != "test-registry" {
				http.Error(w, "bad scope or service", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"token": "` + token + `"}`))
		case "/v2/" + repository + "/manifests/" + Tag:
			if behaviour.manifestStatus != 0 {
				w.WriteHeader(behaviour.manifestStatus)
				return
			}
			if !authorized {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+server.URL+`/token",service="test-registry",scope="repository:`+repository+`:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			if r.Method == http.MethodHead {
				return
			}
			_, _ = w.Write([]byte(`{"schemaVersion": 2, "layers": [{"mediaType": "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip", "digest": "` + testDigest + `", "size": ` + strconv.Itoa(len(behaviour.archive)) + `}]}`))
		case "/v2/" + repository + "/blobs/" + testDigest:
			if !authorized {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if behaviour.blobStatus != 0 {
				w.WriteHeader(behaviour.blobStatus)
				return
			}
			blobs.Add(1)
			_, _ = w.Write(behaviour.archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	registryUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url parse: %v", err)
	}
	return &Source{Registry: registryUrl, Repository: repository}, &blobs
}

func TestDownload(t *testing.T) {
	t.Parallel()

	files := map[string]string{
		FileName:         "the database",
		MetadataFileName: `{"Version":2,"UpdatedAt":"2026-11-10T19:01:23Z","NextUpdate":"2026-11-11T19:01:23Z"}`,
		"README":         "not part of the database",
	}
	good := archive(t, files)
	withoutMetadata := archive(t, map[string]string{FileName: "the database"})

	testCases := []struct {
		name string
		// registries are the sources, in order.
		registries []*registry
		// expectedServedBy is the index of the source the database should come from, or -1 for failure.
		expectedServedBy int
		expectedErr      error
		expectedProgress []string
	}{
		{
			name:             "a registry that challenges for a token, as ghcr.io does",
			registries:       []*registry{{challenge: true, archive: good}},
			expectedServedBy: 0,
			expectedProgress: []string{"downloading the vulnerability database from", testDigest},
		},
		{
			name:             "an anonymous registry, as mirror.gcr.io is",
			registries:       []*registry{{archive: good}},
			expectedServedBy: 0,
		},
		{
			name:             "the second source when the first refuses the manifest",
			registries:       []*registry{{manifestStatus: http.StatusTooManyRequests, archive: good}, {archive: good}},
			expectedServedBy: 1,
			expectedProgress: []string{"could not download the vulnerability database from", "downloading the vulnerability database from"},
		},
		{
			name:             "the second source when the first fails on the blob",
			registries:       []*registry{{challenge: true, blobStatus: http.StatusBadGateway, archive: good}, {archive: good}},
			expectedServedBy: 1,
		},
		{
			name:             "every source failing",
			registries:       []*registry{{manifestStatus: http.StatusTooManyRequests}, {blobStatus: http.StatusInternalServerError, archive: good}},
			expectedServedBy: -1,
			expectedErr:      ErrBlobStatus,
		},
		{
			name:             "an artifact without the metadata",
			registries:       []*registry{{archive: withoutMetadata}},
			expectedServedBy: -1,
			expectedErr:      ErrDatabaseMissing,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var sources []*Source
			var counters []*atomic.Int32
			for i, behaviour := range testCase.registries {
				source, counter := newRegistry(t, "trivy-db-"+strconv.Itoa(i), behaviour)
				sources = append(sources, source)
				counters = append(counters, counter)
			}
			dir := filepath.Join(t.TempDir(), "db")
			var progress strings.Builder

			err := Download(context.Background(), dir, sources, &progress)

			if testCase.expectedServedBy < 0 {
				if err == nil {
					t.Fatalf("%s: expected an error", testCase.name)
				}
				if testCase.expectedErr != nil && !errors.Is(err, testCase.expectedErr) {
					t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expectedErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}
			for i, counter := range counters {
				expected := int32(0)
				if i == testCase.expectedServedBy {
					expected = 1
				}
				if counter.Load() != expected {
					t.Errorf("%s: source %d served the blob %d times, expected %d", testCase.name, i, counter.Load(), expected)
				}
			}
			for _, name := range []string{FileName, MetadataFileName} {
				data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // test fixture
				if err != nil {
					t.Fatalf("%s: read %s: %v", testCase.name, name, err)
				}
				if string(data) != files[name] {
					t.Errorf("%s: %s holds %q, expected %q", testCase.name, name, data, files[name])
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("%s: read dir: %v", testCase.name, err)
			}
			if len(entries) != 2 {
				t.Errorf("%s: expected exactly the two database files, got %v", testCase.name, entries)
			}
			for _, expected := range testCase.expectedProgress {
				if !strings.Contains(progress.String(), expected) {
					t.Errorf("%s: expected progress to mention %q, got %q", testCase.name, expected, progress.String())
				}
			}
		})
	}
}

func TestDownloadReplacesExistingDatabase(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("old"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	source, _ := newRegistry(t, "trivy-db", &registry{archive: archive(t, map[string]string{FileName: "new", MetadataFileName: `{"UpdatedAt":"2026-11-10T00:00:00Z"}`})})

	if err := Download(context.Background(), dir, []*Source{source}, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, FileName)) //nolint:gosec // test fixture
	if err != nil || string(data) != "new" {
		t.Errorf("expected the database replaced, got %q %v", data, err)
	}
}

func TestDownloadArguments(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		dir     string
		sources []*Source
	}{
		{name: "no dir", dir: "", sources: DefaultSources()},
		{name: "no sources", dir: "db", sources: nil},
		{name: "a source without a registry", dir: "db", sources: []*Source{{Repository: "x"}}},
		{name: "a source without a repository", dir: "db", sources: []*Source{{Registry: &url.URL{Scheme: "https", Host: "example.com"}}}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if err := Download(context.Background(), testCase.dir, testCase.sources, nil); err == nil {
				t.Errorf("%s: expected an error", testCase.name)
			}
		})
	}
}

func TestParseBearerChallenge(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		header   string
		expected map[string]string
		ok       bool
	}{
		{
			name:     "ghcr.io",
			header:   `Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:aquasecurity/trivy-db:pull"`,
			expected: map[string]string{"realm": "https://ghcr.io/token", "service": "ghcr.io", "scope": "repository:aquasecurity/trivy-db:pull"},
			ok:       true,
		},
		{
			name:     "case and spacing",
			header:   ` bearer Realm = "https://r.example/t" , Service=r.example`,
			expected: map[string]string{"realm": "https://r.example/t", "service": "r.example"},
			ok:       true,
		},
		{
			name:     "an escaped quote",
			header:   `Bearer realm="https://r.example/t",error_description="a \"quoted\" word"`,
			expected: map[string]string{"realm": "https://r.example/t", "error_description": `a "quoted" word`},
			ok:       true,
		},
		{name: "another scheme", header: `Basic realm="registry"`, ok: false},
		{name: "an unterminated quote", header: `Bearer realm="https://r.example/t`, ok: false},
		{name: "a parameter without a value", header: `Bearer realm`, ok: false},
		{name: "empty", header: ``, ok: false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			params, ok := parseBearerChallenge(testCase.header)
			if ok != testCase.ok {
				t.Fatalf("%s: expected ok %v, got %v (%v)", testCase.name, testCase.ok, ok, params)
			}
			if ok && !maps.Equal(params, testCase.expected) {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expected, params)
			}
		})
	}
}

func TestReadMetadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		content     *string
		expected    time.Time
		expectedErr error
	}{
		{
			name:     "metadata as Trivy writes it",
			content:  new(`{"Version":2,"NextUpdate":"2026-11-11T19:01:23.081218965Z","UpdatedAt":"2026-11-10T19:01:23.081219346Z","DownloadedAt":"0001-01-01T00:00:00Z"}`),
			expected: time.Date(2026, 11, 10, 19, 1, 23, 81219346, time.UTC),
		},
		{name: "no metadata", content: nil, expectedErr: os.ErrNotExist},
		{name: "not JSON", content: new(`not json`), expectedErr: altshiftErrors.ErrParseError},
		{name: "no update time", content: new(`{"Version":2}`), expectedErr: altshiftErrors.ErrValidationError},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if testCase.content != nil {
				if err := os.WriteFile(filepath.Join(dir, MetadataFileName), []byte(*testCase.content), 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
			metadata, err := ReadMetadata(dir)
			if testCase.expectedErr != nil {
				if !errors.Is(err, testCase.expectedErr) {
					t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expectedErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}
			if !metadata.UpdatedAt.Equal(testCase.expected) {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expected, metadata.UpdatedAt)
			}
		})
	}
}
