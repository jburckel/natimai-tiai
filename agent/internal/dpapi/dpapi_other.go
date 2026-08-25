//go:build !windows

// Package dpapi: non-Windows pass-through. DPAPI is Windows-only; on other
// platforms (dev/test) the token is stored as-is. Production runs on Windows.
package dpapi

// Protect returns data unchanged (no OS keystore available); the entropy is
// ignored for the same reason.
func Protect(data, _ []byte) ([]byte, error) { return data, nil }

// Unprotect returns data unchanged.
func Unprotect(data, _ []byte) ([]byte, error) { return data, nil }
