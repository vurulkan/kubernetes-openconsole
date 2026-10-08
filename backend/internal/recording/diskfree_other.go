//go:build !unix

package recording

// diskFree is unknown off unix; only the total quota applies there.
func diskFree(string) (uint64, bool) { return 0, false }
