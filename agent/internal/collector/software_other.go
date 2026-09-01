//go:build !windows

package collector

import "tiai/agent/internal/models"

// readInstalledSoftware reports nothing off Windows: the Uninstall hives are a
// Windows registry concept. nil and not an empty slice, deliberately — an empty
// slice would tell the server "this machine has no software at all", a claim a
// Linux dev build has no business making, and one that would wipe a real list.
func readInstalledSoftware() []models.Software { return nil }
