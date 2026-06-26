//go:build !windows

package identity

// Platform reads are Windows-only; non-Windows builds (dev/test) report no
// hardware anchor, so Resolve falls back to a persisted agent UUID.
func readSMBIOSUUID() string { return "" }

func readMachineGUID() string { return "" }

func readTPMEKHash() string { return "" }
