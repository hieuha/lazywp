package scanner

import (
	"strconv"
	"strings"
)

// CompareVersions compares two version strings segment by segment.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func CompareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	maxLen := max(len(aParts), len(bParts))

	for i := 0; i < maxLen; i++ {
		var aNum, bNum int
		if i < len(aParts) {
			aNum, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bNum, _ = strconv.Atoi(bParts[i])
		}
		if aNum < bNum {
			return -1
		}
		if aNum > bNum {
			return 1
		}
	}
	return 0
}

// IsVulnerable returns true if currentVersion < fixedIn.
// Special cases: empty fixedIn means unfixed (always vulnerable),
// "unfixed" string also means always vulnerable.
func IsVulnerable(currentVersion, fixedIn string) bool {
	if fixedIn == "" || strings.EqualFold(fixedIn, "unfixed") {
		return true
	}
	return CompareVersions(currentVersion, fixedIn) < 0
}
