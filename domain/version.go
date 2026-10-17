package domain

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// Version is a semantic version MAJOR.MINOR.PATCH.
type Version string

// NewVersion validates a version.
func NewVersion(raw string) (Version, error) {
	if !versionPattern.MatchString(raw) {
		return "", errors.New("invalid version: MAJOR.MINOR.PATCH")
	}
	return Version(raw), nil
}

func (v Version) parts() [3]int {
	var out [3]int
	for i, p := range strings.SplitN(string(v), ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

// Less orders versions numerically.
func (v Version) Less(other Version) bool {
	a, b := v.parts(), other.parts()
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
