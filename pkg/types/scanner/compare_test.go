package scanner

import (
	"testing"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

func TestIsVulnerable(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		version  string
		advisory dbTypes.Advisory
		match    matchVersionFunc
		expected bool
	}{
		{
			name:     "npm below patched",
			version:  "4.17.20",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{"<4.17.21"}, PatchedVersions: []string{"4.17.21"}},
			match:    matchNpm,
			expected: true,
		},
		{
			name:     "npm at patched",
			version:  "4.17.21",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{"<4.17.21"}, PatchedVersions: []string{"4.17.21"}},
			match:    matchNpm,
			expected: false,
		},
		{
			name:     "npm patched only",
			version:  "1.0.0",
			advisory: dbTypes.Advisory{PatchedVersions: []string{">=1.1"}},
			match:    matchNpm,
			expected: true,
		},
		{
			name:     "npm unaffected wins over vulnerable range",
			version:  "1.0.5",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{"<2.0.0"}, UnaffectedVersions: []string{">=1.0.5 <1.1.0"}},
			match:    matchNpm,
			expected: false,
		},
		{
			name:     "npm prerelease inside range",
			version:  "1.0.0-alpha.1",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{"<1.0.0"}},
			match:    matchNpm,
			expected: true,
		},
		{
			name:     "empty vulnerable version detects anyway",
			version:  "1.0.0",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{""}},
			match:    matchNpm,
			expected: true,
		},
		{
			name:     "no versions at all",
			version:  "1.0.0",
			advisory: dbTypes.Advisory{},
			match:    matchNpm,
			expected: false,
		},
		{
			name:     "unparsable version",
			version:  "not a version",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{"<1.0.0"}},
			match:    matchNpm,
			expected: false,
		},
		{
			name:     "pep440 pre-release",
			version:  "4.2rc1",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{"<4.2.1"}, PatchedVersions: []string{"4.2.1"}},
			match:    matchPep440,
			expected: true,
		},
		{
			name:     "pep440 patched",
			version:  "4.2.1",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{">=4.2, <4.2.1"}, PatchedVersions: []string{"4.2.1"}},
			match:    matchPep440,
			expected: false,
		},
		{
			name:     "generic (go) pseudo version",
			version:  "v0.0.0-20220101000000-abcdef123456",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{"<0.1.0"}, PatchedVersions: []string{"0.1.0"}},
			match:    matchGeneric,
			expected: true,
		},
		{
			name:     "generic multiple ranges",
			version:  "2.5.0",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{">=2.0.0, <2.4.0", ">=3.0.0, <3.1.0"}, PatchedVersions: []string{"2.4.0", "3.1.0"}},
			match:    matchGeneric,
			expected: false,
		},
		{
			name:     "maven",
			version:  "2.14.1",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{"<2.15.0"}, PatchedVersions: []string{"2.15.0"}},
			match:    matchMaven,
			expected: true,
		},
		{
			name:     "maven qualifier ordering",
			version:  "2.15.0-rc1",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{"<2.15.0"}, PatchedVersions: []string{"2.15.0"}},
			match:    matchMaven,
			expected: true,
		},
		{
			name:     "rubygems",
			version:  "6.1.7.2",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{">= 6.1.0, < 6.1.7.3"}, PatchedVersions: []string{"~> 6.1.7.3"}},
			match:    matchRubygems,
			expected: true,
		},
		{
			name:     "bitnami",
			version:  "1.2.3-4",
			advisory: dbTypes.Advisory{VulnerableVersions: []string{"<1.2.4"}, PatchedVersions: []string{"1.2.4"}},
			match:    matchBitnami,
			expected: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := isVulnerable(testCase.version, testCase.advisory, testCase.match); got != testCase.expected {
				t.Errorf("expected %t, got %t", testCase.expected, got)
			}
		})
	}
}

func TestLessThan(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		lessThan  func(installed, fixed string) (bool, error)
		installed string
		fixed     string
		expected  bool
		err       bool
	}{
		{name: "apk less", lessThan: apkLessThan, installed: "1.36.1-r15", fixed: "1.36.1-r16", expected: true},
		{name: "apk equal", lessThan: apkLessThan, installed: "1.36.1-r16", fixed: "1.36.1-r16", expected: false},
		{name: "apk greater", lessThan: apkLessThan, installed: "1.37.0-r0", fixed: "1.36.1-r16", expected: false},
		{name: "apk invalid", lessThan: apkLessThan, installed: "not-a-version!", fixed: "1.36.1-r16", err: true},
		{name: "deb less", lessThan: debLessThan, installed: "3.0.11-1~deb12u1", fixed: "3.0.11-1~deb12u2", expected: true},
		{name: "deb epoch wins", lessThan: debLessThan, installed: "1:1.0-1", fixed: "2.0-1", expected: false},
		{name: "deb tilde sorts before release", lessThan: debLessThan, installed: "1.0~rc1-1", fixed: "1.0-1", expected: true},
		{name: "deb invalid", lessThan: debLessThan, installed: "", fixed: "1.0-1", err: true},
		{name: "rpm less", lessThan: rpmLessThan, installed: "1:3.0.7-25.el9_2", fixed: "1:3.0.7-25.el9_3", expected: true},
		{name: "rpm epoch wins", lessThan: rpmLessThan, installed: "1:1.0-1.el9", fixed: "2.0-1.el9", expected: false},
		{name: "rpm equal", lessThan: rpmLessThan, installed: "5.1.8-6.el9", fixed: "5.1.8-6.el9", expected: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := testCase.lessThan(testCase.installed, testCase.fixed)
			if testCase.err {
				if err == nil {
					t.Fatalf("expected an error, got %t", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != testCase.expected {
				t.Errorf("expected %t, got %t", testCase.expected, got)
			}
		})
	}
}
