//go:build !windows

package config

// No registry off Windows, and dpapi is a pass-through there anyway: entropy
// would protect nothing. Dev/test store the token as-is.
func readTokenEntropy() []byte   { return nil }
func ensureTokenEntropy() []byte { return nil }
