package secrets

import "syscall"

// changeTime is when the file's contents or attributes were last changed.
// Unlike the modification time, a program cannot set it back.
func changeTime(st *syscall.Stat_t) int64 { return st.Ctim.Nano() }
