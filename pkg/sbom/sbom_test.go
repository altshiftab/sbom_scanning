package sbom

import (
	"errors"
	"slices"
	"testing"

	sbomScanningErrors "github.com/altshiftab/sbom_scanning/pkg/errors"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

type expectedPackage struct {
	name        string
	version     string
	purl        string
	srcName     string
	srcVersion  string
	contentSets []string
	nvr         string
}

func TestParse(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		data     string
		expected []expectedPackage
		err      error
	}{
		{
			name: "cyclonedx json",
			data: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"metadata": {
					"component": {"type": "application", "name": "app", "version": "1.0.0", "purl": "pkg:npm/app@1.0.0"}
				},
				"components": [
					{"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
					{"type": "library", "group": "@babel", "name": "core", "version": "7.0.0", "purl": "pkg:npm/%40babel/core@7.0.0"},
					{"type": "library", "group": "org.apache.logging.log4j", "name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
					{"type": "library", "name": "no-purl", "version": "1.0.0"},
					{"type": "library", "name": "bad-purl", "version": "1.0.0", "purl": "not a purl"},
					{"type": "library", "name": "no-version", "purl": "pkg:npm/no-version"},
					{"type": "library", "name": "purl-version", "purl": "pkg:npm/purl-version@2.0.0"},
					{
						"type": "application", "name": "nested", "version": "1", "components": [
							{"type": "library", "name": "inner", "version": "3.0.0", "purl": "pkg:pypi/inner@3.0.0"}
						]
					}
				]
			}`,
			expected: []expectedPackage{
				{name: "app", version: "1.0.0", purl: "pkg:npm/app@1.0.0"},
				{name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20"},
				{name: "@babel/core", version: "7.0.0", purl: "pkg:npm/%40babel/core@7.0.0"},
				{name: "org.apache.logging.log4j:log4j-core", version: "2.14.1", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
				{name: "purl-version", version: "2.0.0", purl: "pkg:npm/purl-version@2.0.0"},
				{name: "inner", version: "3.0.0", purl: "pkg:pypi/inner@3.0.0"},
			},
		},
		{
			name: "cyclonedx json os packages (trivy)",
			data: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"components": [
					{
						"type": "library", "name": "libssl3", "version": "3.0.11-1~deb12u2",
						"purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12.4",
						"properties": [
							{"name": "aquasecurity:trivy:PkgType", "value": "debian"},
							{"name": "aquasecurity:trivy:SrcName", "value": "openssl"},
							{"name": "aquasecurity:trivy:SrcVersion", "value": "3.0.11"},
							{"name": "aquasecurity:trivy:SrcRelease", "value": "1~deb12u2"}
						]
					},
					{
						"type": "library", "name": "bash", "version": "1:5.2.15-2+b2",
						"purl": "pkg:deb/debian/bash@5.2.15-2%2Bb2?arch=amd64&distro=debian-12.4&epoch=1",
						"properties": [
							{"name": "aquasecurity:trivy:SrcName", "value": "bash"},
							{"name": "aquasecurity:trivy:SrcVersion", "value": "5.2.15"},
							{"name": "aquasecurity:trivy:SrcRelease", "value": "2+b2"},
							{"name": "aquasecurity:trivy:SrcEpoch", "value": "1"}
						]
					},
					{
						"type": "library", "name": "openssl-libs", "version": "1:3.0.7-25.el9_3",
						"purl": "pkg:rpm/redhat/openssl-libs@3.0.7-25.el9_3?arch=x86_64&distro=redhat-9.3&epoch=1"
					},
					{
						"type": "library", "name": "openssl-libs", "version": "1:3.0.7-25.el9_3",
						"purl": "pkg:rpm/redhat/openssl-libs@3.0.7-25.el9_3?arch=x86_64&distro=redhat-9.3&epoch=1",
						"properties": [
							{"name": "aquasecurity:trivy:SrcName", "value": "openssl"},
							{"name": "aquasecurity:trivy:SrcVersion", "value": "3.0.7"},
							{"name": "aquasecurity:trivy:SrcRelease", "value": "25.el9_3"},
							{"name": "aquasecurity:trivy:SrcEpoch", "value": "1"},
							{"name": "aquasecurity:trivy:ContentSet", "value": "rhel-9-for-x86_64-baseos-rpms__9"},
							{"name": "aquasecurity:trivy:ContentSet", "value": "rhel-9-for-x86_64-appstream-rpms__9_DOT_2"},
							{"name": "aquasecurity:trivy:NVR", "value": "ubi9-container-9.3-1361"},
							{"name": "aquasecurity:trivy:Arch", "value": "x86_64"}
						]
					}
				]
			}`,
			expected: []expectedPackage{
				{name: "libssl3", version: "3.0.11-1~deb12u2", purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12.4", srcName: "openssl", srcVersion: "3.0.11-1~deb12u2"},
				{name: "bash", version: "1:5.2.15-2+b2", purl: "pkg:deb/debian/bash@5.2.15-2%2Bb2?arch=amd64&distro=debian-12.4&epoch=1", srcName: "bash", srcVersion: "1:5.2.15-2+b2"},
				{name: "openssl-libs", version: "1:3.0.7-25.el9_3", purl: "pkg:rpm/redhat/openssl-libs@3.0.7-25.el9_3?arch=x86_64&distro=redhat-9.3&epoch=1", srcName: "openssl-libs", srcVersion: "1:3.0.7-25.el9_3"},
				{
					name: "openssl-libs", version: "1:3.0.7-25.el9_3", purl: "pkg:rpm/redhat/openssl-libs@3.0.7-25.el9_3?arch=x86_64&distro=redhat-9.3&epoch=1", srcName: "openssl", srcVersion: "1:3.0.7-25.el9_3",
					contentSets: []string{"rhel-9-for-x86_64-baseos-rpms__9", "rhel-9-for-x86_64-appstream-rpms__9_DOT_2"}, nvr: "ubi9-container-9.3-1361-x86_64",
				},
			},
		},
		{
			name: "cyclonedx json os packages (syft upstream qualifier)",
			data: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"components": [
					{
						"type": "library", "name": "libssl3", "version": "3.0.11-1~deb12u2",
						"purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl"
					},
					{
						"type": "library", "name": "libgcc-s1", "version": "12.2.0-14",
						"purl": "pkg:deb/debian/libgcc-s1@12.2.0-14?arch=amd64&distro=debian-12&upstream=gcc-12@12.2.0-14"
					},
					{
						"type": "library", "name": "bash", "version": "5.1.8-6.el9",
						"purl": "pkg:rpm/redhat/bash@5.1.8-6.el9?arch=x86_64&distro=rhel-9.2&upstream=bash-5.1.8-6.el9.src.rpm"
					},
					{
						"type": "library", "name": "ssl_client", "version": "1.36.1-r15",
						"purl": "pkg:apk/alpine/ssl_client@1.36.1-r15?arch=x86_64&distro=alpine-3.18.4&upstream=busybox"
					}
				]
			}`,
			expected: []expectedPackage{
				{name: "libssl3", version: "3.0.11-1~deb12u2", purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl", srcName: "openssl", srcVersion: "3.0.11-1~deb12u2"},
				{name: "libgcc-s1", version: "12.2.0-14", purl: "pkg:deb/debian/libgcc-s1@12.2.0-14?arch=amd64&distro=debian-12&upstream=gcc-12%4012.2.0-14", srcName: "gcc-12", srcVersion: "12.2.0-14"},
				{name: "bash", version: "5.1.8-6.el9", purl: "pkg:rpm/redhat/bash@5.1.8-6.el9?arch=x86_64&distro=rhel-9.2&upstream=bash-5.1.8-6.el9.src.rpm", srcName: "bash", srcVersion: "5.1.8-6.el9"},
				{name: "ssl_client", version: "1.36.1-r15", purl: "pkg:apk/alpine/ssl_client@1.36.1-r15?arch=x86_64&distro=alpine-3.18.4&upstream=busybox", srcName: "busybox", srcVersion: "1.36.1-r15"},
			},
		},
		{
			name: "cyclonedx xml",
			data: `<?xml version="1.0" encoding="UTF-8"?>
				<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
					<components>
						<component type="library">
							<name>lodash</name>
							<version>4.17.20</version>
							<purl>pkg:npm/lodash@4.17.20</purl>
						</component>
						<component type="library">
							<name>libssl3</name>
							<version>3.0.11-1~deb12u2</version>
							<purl>pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12</purl>
							<properties>
								<property name="aquasecurity:trivy:SrcName">openssl</property>
								<property name="aquasecurity:trivy:SrcVersion">3.0.11</property>
								<property name="aquasecurity:trivy:SrcRelease">1~deb12u2</property>
							</properties>
							<components>
								<component type="library">
									<name>nested</name>
									<version>1.0.0</version>
									<purl>pkg:gem/nested@1.0.0</purl>
								</component>
							</components>
						</component>
					</components>
				</bom>`,
			expected: []expectedPackage{
				{name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20"},
				{name: "libssl3", version: "3.0.11-1~deb12u2", purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12", srcName: "openssl", srcVersion: "3.0.11-1~deb12u2"},
				{name: "nested", version: "1.0.0", purl: "pkg:gem/nested@1.0.0"},
			},
		},
		{
			name: "spdx json",
			data: `{
				"spdxVersion": "SPDX-2.3",
				"SPDXID": "SPDXRef-DOCUMENT",
				"packages": [
					{
						"name": "lodash", "SPDXID": "SPDXRef-Package-1", "versionInfo": "4.17.20",
						"externalRefs": [
							{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20"}
						]
					},
					{
						"name": "log4j-core", "SPDXID": "SPDXRef-Package-2", "versionInfo": "2.14.1",
						"externalRefs": [
							{"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
							{"referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
						]
					},
					{
						"name": "libssl3", "SPDXID": "SPDXRef-Package-3", "versionInfo": "3.0.11-1~deb12u2",
						"sourceInfo": "built package from: openssl 3.0.11-1~deb12u2",
						"externalRefs": [
							{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12"}
						]
					},
					{"name": "no-purl", "SPDXID": "SPDXRef-Package-4", "versionInfo": "1.0.0"}
				]
			}`,
			expected: []expectedPackage{
				{name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20"},
				{name: "org.apache.logging.log4j:log4j-core", version: "2.14.1", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
				{name: "libssl3", version: "3.0.11-1~deb12u2", purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12", srcName: "openssl", srcVersion: "3.0.11-1~deb12u2"},
			},
		},
		{
			name: "leading whitespace, duplicate names and member-name case are tolerated",
			data: "\n\t {\"bomFormat\": \"CycloneDX\", \"bomFormat\": \"CycloneDX\", \"Components\": [{\"Name\": \"a\", \"Version\": \"1\", \"PURL\": \"pkg:npm/a@1\"}]}",
			expected: []expectedPackage{
				{name: "a", version: "1", purl: "pkg:npm/a@1"},
			},
		},
		{
			name:     "cyclonedx json without components",
			data:     `{"bomFormat": "CycloneDX", "specVersion": "1.5"}`,
			expected: nil,
		},
		{
			name: "empty",
			data: "  \n",
			err:  altshiftErrors.ErrParseError,
		},
		{
			name: "unknown json document",
			data: `{"hello": "world"}`,
			err:  sbomScanningErrors.ErrUnexpectedSbomFormat,
		},
		{
			name: "not json or xml",
			data: `hello`,
			err:  sbomScanningErrors.ErrUnexpectedSbomFormat,
		},
		{
			name: "malformed json",
			data: `{"bomFormat": "CycloneDX", "components": [`,
			err:  altshiftErrors.ErrParseError,
		},
		{
			name: "malformed xml",
			data: `<bom><components>`,
			err:  altshiftErrors.ErrParseError,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			packages, err := Parse([]byte(testCase.data))
			if testCase.err != nil {
				if !errors.Is(err, testCase.err) {
					t.Fatalf("expected error %v, got %v", testCase.err, err)
				}
				if !errors.Is(err, altshiftErrors.ErrParseError) {
					t.Fatalf("expected the error to wrap ErrParseError, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(packages) != len(testCase.expected) {
				t.Fatalf("expected %d packages, got %d: %+v", len(testCase.expected), len(packages), packages)
			}
			for i, expected := range testCase.expected {
				p := packages[i]
				if p.Purl == nil {
					t.Fatalf("package %d: nil purl", i)
				}
				if p.Name != expected.name || p.Version != expected.version || p.Purl.String() != expected.purl || p.SrcName != expected.srcName || p.SrcVersion != expected.srcVersion || !slices.Equal(p.ContentSets, expected.contentSets) || p.Nvr != expected.nvr {
					t.Errorf(
						"package %d: expected %+v, got {name: %q, version: %q, purl: %q, srcName: %q, srcVersion: %q, contentSets: %v, nvr: %q}",
						i, expected, p.Name, p.Version, p.Purl.String(), p.SrcName, p.SrcVersion, p.ContentSets, p.Nvr,
					)
				}
			}
		})
	}
}

func TestParseUpstream(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		purlType        string
		upstream        string
		expectedName    string
		expectedVersion string
	}{
		{name: "name only", purlType: "deb", upstream: "openssl", expectedName: "openssl"},
		{name: "name and version", purlType: "deb", upstream: "gcc-12@12.2.0-14", expectedName: "gcc-12", expectedVersion: "12.2.0-14"},
		{name: "source rpm", purlType: "rpm", upstream: "bash-5.1.8-6.el9.src.rpm", expectedName: "bash", expectedVersion: "5.1.8-6.el9"},
		{name: "source rpm with dashes in name", purlType: "rpm", upstream: "python3-setuptools-53.0.0-12.el9.src.rpm", expectedName: "python3-setuptools", expectedVersion: "53.0.0-12.el9"},
		{name: "source rpm without release falls back", purlType: "rpm", upstream: "bash-5.1.8.src.rpm", expectedName: "", expectedVersion: ""},
		{name: "source rpm without version falls back", purlType: "rpm", upstream: "bash.src.rpm", expectedName: "", expectedVersion: ""},
		{name: "rpm name only", purlType: "rpm", upstream: "bash", expectedName: "bash"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			name, version := parseUpstream(testCase.purlType, testCase.upstream)
			if name != testCase.expectedName || version != testCase.expectedVersion {
				t.Errorf("expected (%q, %q), got (%q, %q)", testCase.expectedName, testCase.expectedVersion, name, version)
			}
		})
	}
}

func TestFormatVersion(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		epoch    string
		version  string
		release  string
		expected string
	}{
		{name: "version only", version: "1.2.3", expected: "1.2.3"},
		{name: "version and release", version: "1.2.3", release: "4.el9", expected: "1.2.3-4.el9"},
		{name: "zero epoch", epoch: "0", version: "1.2.3", release: "4", expected: "1.2.3-4"},
		{name: "epoch", epoch: "2", version: "1.2.3", release: "4", expected: "2:1.2.3-4"},
		{name: "unparsable epoch", epoch: "x", version: "1.2.3", expected: "1.2.3"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := formatVersion(testCase.epoch, testCase.version, testCase.release); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}
