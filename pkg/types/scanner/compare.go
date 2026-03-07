package scanner

import (
	"fmt"
	"slices"
	"strings"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	gem "github.com/aquasecurity/go-gem-version"
	npm "github.com/aquasecurity/go-npm-version/pkg"
	pep440 "github.com/aquasecurity/go-pep440-version"
	goversion "github.com/aquasecurity/go-version/pkg/version"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	bitnami "github.com/bitnami/go-version/pkg/version"
	apk "github.com/knqyf263/go-apk-version"
	deb "github.com/knqyf263/go-deb-version"
	rpm "github.com/knqyf263/go-rpm-version"
	mvn "github.com/masahiro331/go-mvn-version"
)

type matchVersionFunc func(currentVersion, constraint string) (bool, error)

// isVulnerable checks if the package version is vulnerable to the advisory.
// This is a direct port of the logic from trivy's compare.IsVulnerable.
func isVulnerable(pkgVer string, advisory dbTypes.Advisory, match matchVersionFunc) bool {
	if slices.Contains(append(advisory.VulnerableVersions, advisory.PatchedVersions...), "") {
		return true
	}

	var matched bool
	var err error

	if len(advisory.VulnerableVersions) != 0 {
		matched, err = match(pkgVer, strings.Join(advisory.VulnerableVersions, " || "))
		if err != nil || !matched {
			return false
		}
	}

	secureVersions := append(advisory.PatchedVersions, advisory.UnaffectedVersions...)
	if len(secureVersions) == 0 {
		return matched
	}

	matched, err = match(pkgVer, strings.Join(secureVersions, " || "))
	if err != nil {
		return false
	}
	return !matched
}

// isOSVulnerable checks if an OS package version is less than the fixed version.
// If fixedVersion is empty, the vulnerability is unfixed and the package is considered vulnerable.
func isOSVulnerable(installed, fixed string, cmp func(installed, fixed string) (bool, error)) bool {
	if fixed == "" {
		return true
	}
	less, err := cmp(installed, fixed)
	if err != nil {
		return false
	}
	return less
}

func matchGeneric(currentVersion, constraint string) (bool, error) {
	ver, err := goversion.Parse(currentVersion)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("version error (%s): %w", currentVersion, err))
	}
	c, err := goversion.NewConstraints(constraint)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("constraint error (%s): %w", constraint, err))
	}
	return c.Check(ver), nil
}

func matchNpm(currentVersion, constraint string) (bool, error) {
	v, err := npm.NewVersion(currentVersion)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("npm version error (%s): %w", currentVersion, err))
	}
	c, err := npm.NewConstraints(constraint, npm.WithPreRelease(true))
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("npm constraint error (%s): %w", constraint, err))
	}
	return c.Check(v), nil
}

func matchPep440(currentVersion, constraint string) (bool, error) {
	v, err := pep440.Parse(currentVersion)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("python version error (%s): %w", currentVersion, err))
	}
	c, err := pep440.NewSpecifiers(constraint, pep440.WithPreRelease(true))
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("python constraint error (%s): %w", constraint, err))
	}
	return c.Check(v), nil
}

func matchRubygems(currentVersion, constraint string) (bool, error) {
	v, err := gem.NewVersion(currentVersion)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("rubygems version error (%s): %w", currentVersion, err))
	}
	c, err := gem.NewConstraints(constraint)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("rubygems constraint error (%s): %w", constraint, err))
	}
	return c.Check(v), nil
}

func matchMaven(currentVersion, constraint string) (bool, error) {
	v, err := mvn.NewVersion(currentVersion)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("maven version error (%s): %w", currentVersion, err))
	}
	c, err := mvn.NewComparer(constraint)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("maven constraint error (%s): %w", constraint, err))
	}
	return c.Check(v), nil
}

func matchBitnami(currentVersion, constraint string) (bool, error) {
	v, err := bitnami.Parse(currentVersion)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("bitnami version error (%s): %w", currentVersion, err))
	}
	c, err := bitnami.NewConstraints(constraint)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("bitnami constraint error (%s): %w", constraint, err))
	}
	return c.Check(v), nil
}

func apkLessThan(installed, fixed string) (bool, error) {
	i, err := apk.NewVersion(installed)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("apk version error (%s): %w", installed, err))
	}
	f, err := apk.NewVersion(fixed)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("apk version error (%s): %w", fixed, err))
	}
	return i.LessThan(f), nil
}

func debLessThan(installed, fixed string) (bool, error) {
	i, err := deb.NewVersion(installed)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("deb version error (%s): %w", installed, err))
	}
	f, err := deb.NewVersion(fixed)
	if err != nil {
		return false, motmedelErrors.NewWithTrace(fmt.Errorf("deb version error (%s): %w", fixed, err))
	}
	return i.LessThan(f), nil
}

func rpmLessThan(installed, fixed string) (bool, error) {
	i := rpm.NewVersion(installed)
	f := rpm.NewVersion(fixed)
	return i.LessThan(f), nil
}
