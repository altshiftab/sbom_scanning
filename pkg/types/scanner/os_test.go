package scanner

import (
	"testing"

	"github.com/package-url/packageurl-go"
)

func TestPurlOsInfo(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		purl     string
		expected *osInfo
	}{
		{name: "syft alpine", purl: "pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64&distro=alpine-3.18.4", expected: &osInfo{family: osFamilyAlpine, version: "3.18.4"}},
		{name: "trivy alpine (bare version, family in namespace)", purl: "pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64&distro=3.18.4", expected: &osInfo{family: osFamilyAlpine, version: "3.18.4"}},
		{name: "alpine edge", purl: "pkg:apk/alpine/busybox@1.36.1-r15?distro=alpine-edge", expected: &osInfo{family: osFamilyAlpine, version: "edge"}},
		{name: "wolfi without version", purl: "pkg:apk/wolfi/glibc@2.38-r0?distro=wolfi", expected: &osInfo{family: osFamilyWolfi}},
		{name: "wolfi dated version", purl: "pkg:apk/wolfi/glibc@2.38-r0?distro=wolfi-20230201", expected: &osInfo{family: osFamilyWolfi, version: "20230201"}},
		{name: "chainguard", purl: "pkg:apk/chainguard/glibc@2.38-r0?distro=chainguard", expected: &osInfo{family: osFamilyChainguard}},
		{name: "trivy debian", purl: "pkg:deb/debian/libssl3@3.0.11?distro=debian-12.4", expected: &osInfo{family: osFamilyDebian, version: "12.4"}},
		{name: "syft debian", purl: "pkg:deb/debian/libssl3@3.0.11?arch=amd64&distro=debian-12", expected: &osInfo{family: osFamilyDebian, version: "12"}},
		{name: "ubuntu", purl: "pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-22.04", expected: &osInfo{family: osFamilyUbuntu, version: "22.04"}},
		{name: "trivy redhat", purl: "pkg:rpm/redhat/openssl@3.0.7?distro=redhat-9.3", expected: &osInfo{family: osFamilyRedHat, version: "9.3"}},
		{name: "syft rhel", purl: "pkg:rpm/redhat/openssl@3.0.7?distro=rhel-9.2", expected: &osInfo{family: osFamilyRedHat, version: "9.2"}},
		{name: "centos", purl: "pkg:rpm/centos/openssl@1.1.1k?distro=centos-7.9.2009", expected: &osInfo{family: osFamilyRedHat, version: "7.9.2009"}},
		{name: "rocky", purl: "pkg:rpm/rocky/bash@5.1.8?distro=rocky-9.3", expected: &osInfo{family: osFamilyRocky, version: "9.3"}},
		{name: "trivy alma", purl: "pkg:rpm/alma/bash@5.1.8?distro=alma-9.3", expected: &osInfo{family: osFamilyAlma, version: "9.3"}},
		{name: "syft almalinux", purl: "pkg:rpm/almalinux/bash@5.1.8?distro=almalinux-9.3", expected: &osInfo{family: osFamilyAlma, version: "9.3"}},
		{name: "trivy oracle", purl: "pkg:rpm/oracle/bash@5.1.8?distro=oracle-8.9", expected: &osInfo{family: osFamilyOracle, version: "8.9"}},
		{name: "syft ol", purl: "pkg:rpm/ol/bash@5.1.8?distro=ol-8.9", expected: &osInfo{family: osFamilyOracle, version: "8.9"}},
		{name: "trivy amazon", purl: "pkg:rpm/amazon/curl@8.3.0?distro=amazon-2023", expected: &osInfo{family: osFamilyAmazon, version: "2023"}},
		{name: "syft amzn", purl: "pkg:rpm/amzn/curl@8.3.0?distro=amzn-2", expected: &osInfo{family: osFamilyAmazon, version: "2"}},
		{name: "photon", purl: "pkg:rpm/photon/openssl@3.0.10?distro=photon-4.0", expected: &osInfo{family: osFamilyPhoton, version: "4.0"}},
		{name: "sles", purl: "pkg:rpm/suse/openssl@3.0.8?distro=sles-15.5", expected: &osInfo{family: osFamilySles, version: "15.5"}},
		{name: "sle micro", purl: "pkg:rpm/suse/openssl@3.0.8?distro=slem-5.5", expected: &osInfo{family: osFamilySleMicro, version: "5.5"}},
		{name: "opensuse leap", purl: "pkg:rpm/opensuse/openssl@3.0.8?distro=opensuse-leap-15.5", expected: &osInfo{family: osFamilyOpenSuseLeap, version: "15.5"}},
		{name: "old opensuse leap spelling", purl: "pkg:rpm/opensuse/openssl@3.0.8?distro=opensuse.leap-15.5", expected: &osInfo{family: osFamilyOpenSuseLeap, version: "15.5"}},
		{name: "opensuse tumbleweed", purl: "pkg:rpm/opensuse/openssl@3.0.8?distro=opensuse-tumbleweed", expected: &osInfo{family: osFamilyOpenSuseTumbleweed}},
		{name: "opensuse tumbleweed with snapshot", purl: "pkg:rpm/opensuse/openssl@3.0.8?distro=opensuse-tumbleweed-20240101", expected: &osInfo{family: osFamilyOpenSuseTumbleweed, version: "20240101"}},
		{name: "bare version with namespace", purl: "pkg:deb/debian/libssl3@3.0.11?distro=12", expected: &osInfo{family: osFamilyDebian, version: "12"}},
		{name: "upper case", purl: "pkg:deb/debian/libssl3@3.0.11?distro=Debian-12", expected: &osInfo{family: osFamilyDebian, version: "12"}},
		{name: "no distro", purl: "pkg:deb/debian/libssl3@3.0.11?arch=amd64", expected: nil},
		{name: "unknown distro", purl: "pkg:rpm/fedora/bash@5.2.26?distro=fedora-40", expected: nil},
		{name: "bare version without known namespace", purl: "pkg:rpm/fedora/bash@5.2.26?distro=40", expected: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			purl, err := packageurl.FromString(testCase.purl)
			if err != nil {
				t.Fatalf("purl: %v", err)
			}
			info, ok := purlOsInfo(&purl)
			if testCase.expected == nil {
				if ok {
					t.Fatalf("expected no os info, got %+v", info)
				}
				return
			}
			if !ok {
				t.Fatalf("expected %+v, got none", testCase.expected)
			}
			if *info != *testCase.expected {
				t.Errorf("expected %+v, got %+v", testCase.expected, info)
			}
		})
	}
}

func TestVersionHelpers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		f        func(string) string
		input    string
		expected string
	}{
		{name: "major of x.y.z", f: majorVersion, input: "8.1.2", expected: "8"},
		{name: "major of x", f: majorVersion, input: "8", expected: "8"},
		{name: "major of empty", f: majorVersion, input: "", expected: ""},
		{name: "minor of x.y.z", f: minorVersion, input: "3.17.2", expected: "3.17"},
		{name: "minor of x.y", f: minorVersion, input: "3.17", expected: "3.17"},
		{name: "minor of x", f: minorVersion, input: "edge", expected: "edge"},
		{name: "amazon 2", f: amazonRelease, input: "2", expected: "2"},
		{name: "amazon 2 with codename", f: amazonRelease, input: "2 (Karoo)", expected: "2"},
		{name: "amazon 2022", f: amazonRelease, input: "2022", expected: "2022"},
		{name: "amazon 2023 dated", f: amazonRelease, input: "2023.3.20240108", expected: "2023"},
		{name: "amazon 1 dated", f: amazonRelease, input: "2018.03", expected: "1"},
		{name: "amazon empty", f: amazonRelease, input: "", expected: "1"},
		{name: "rpm release", f: rpmRelease, input: "1:5.1.8-6.el9", expected: "6.el9"},
		{name: "rpm release without release", f: rpmRelease, input: "5.1.8", expected: ""},
		{name: "oracle normal flavor", f: oraclePackageFlavor, input: "12.el8_9", expected: "normal"},
		{name: "oracle ksplice flavor", f: oraclePackageFlavor, input: "12.ksplice1.el8_9", expected: "ksplice"},
		{name: "oracle fips flavor", f: oraclePackageFlavor, input: "1:1.1.1k-12.el8_fips", expected: "fips"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := testCase.f(testCase.input); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}

func TestAddModularNamespace(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		pkgName  string
		label    string
		expected string
	}{
		{name: "no label", pkgName: "npm", label: "", expected: "npm"},
		{name: "full label", pkgName: "npm", label: "nodejs:12:8030020201124152102:229f0a1c", expected: "nodejs:12::npm"},
		{name: "short label", pkgName: "npm", label: "nodejs:12", expected: "npm"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := addModularNamespace(testCase.pkgName, testCase.label); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}

func TestIsOsVulnerable(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		installed     string
		fixed         string
		reportUnfixed bool
		expected      bool
	}{
		{name: "below fixed", installed: "1.0-1", fixed: "1.0-2", expected: true},
		{name: "at fixed", installed: "1.0-2", fixed: "1.0-2", expected: false},
		{name: "unfixed reported", installed: "1.0-1", fixed: "", reportUnfixed: true, expected: true},
		{name: "unfixed not reported", installed: "1.0-1", fixed: "", reportUnfixed: false, expected: false},
		{name: "unparsable installed", installed: "", fixed: "1.0-2", expected: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := isOsVulnerable(testCase.installed, testCase.fixed, debLessThan, testCase.reportUnfixed); got != testCase.expected {
				t.Errorf("expected %t, got %t", testCase.expected, got)
			}
		})
	}
}
