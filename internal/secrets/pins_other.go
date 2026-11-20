//go:build !linux && !darwin

package secrets

import "syscall"

// changeTime is not read on this system; the other parts of a file's identity
// still are.
func changeTime(*syscall.Stat_t) int64 { return 0 }
