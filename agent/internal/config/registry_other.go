//go:build !windows

package config

// applyRegistryOverrides is a no-op off Windows (no registry).
func applyRegistryOverrides(*Config) {}
