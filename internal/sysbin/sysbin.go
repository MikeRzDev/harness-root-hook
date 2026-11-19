// Package sysbin locates system executables in fixed directories. It never
// consults PATH, so a caller-controlled PATH cannot substitute a program that
// would receive or collect a password.
package sysbin

import (
	"os"
	"path/filepath"
)

// Dirs are searched in order. Root-owned system directories come first.
var Dirs = []string{
	"/usr/bin", "/bin", "/usr/sbin", "/sbin",
	"/run/wrappers/bin", "/run/current-system/sw/bin",
	"/usr/local/bin", "/opt/homebrew/bin",
}

// Find returns the first executable regular file named name, or "".
func Find(name string) string {
	for _, dir := range Dirs {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return path
		}
	}
	return ""
}
