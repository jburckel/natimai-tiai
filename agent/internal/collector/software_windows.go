package collector

import (
	"golang.org/x/sys/windows/registry"

	"tiai/agent/internal/logging"
	"tiai/agent/internal/models"
)

// The two Uninstall hives. The second is not optional: a 64-bit Windows keeps
// every 32-bit program there and nowhere else, and skipping it loses a good
// third of what a parc runs. Read by path rather than through the WOW64 view
// flags — the agent is a 64-bit binary, so the redirected path is directly
// visible and needs no registry redirection dance.
var uninstallKeys = map[string]string{
	softwareSourceHKLM: `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	softwareSourceWOW:  `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// readInstalledSoftware walks both Uninstall hives.
//
// Native registry reads, no WMI and no PowerShell: a few dozen milliseconds and
// no side effect, against the minutes and the per-machine event log entry that
// Win32_Product would cost (see software.go).
//
// Returns a non-nil empty slice when the hives hold nothing worth listing, and
// that distinction is load-bearing: nil would tell the server "not read" and
// leave the previous list in place, where an empty slice clears it.
func readInstalledSoftware() []models.Software {
	out := make([]models.Software, 0, 256)
	for source, path := range uninstallKeys {
		entries, err := readUninstallHive(path)
		if err != nil {
			// A missing WOW6432Node is normal on a 32-bit-free install; a
			// missing 64-bit hive is not, but neither is worth failing the whole
			// inventory over.
			logging.Debugf("agent: inventory: uninstall hive %s: %v", path, err)
			continue
		}
		out = append(out, buildSoftware(entries, source)...)
	}
	return dedupeSoftware(out)
}

// readUninstallHive reads every subkey of one Uninstall path.
func readUninstallHive(path string) ([]rawSoftware, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	out := make([]rawSoftware, 0, len(names))
	for _, name := range names {
		key, err := registry.OpenKey(root, name, registry.QUERY_VALUE)
		if err != nil {
			// A key the agent cannot open is skipped rather than fatal: an
			// installer can leave one with an ACL nobody expected.
			continue
		}
		out = append(out, readUninstallEntry(key))
		key.Close()
	}
	return out, nil
}

// readUninstallEntry reads the values the filtering and the report need.
//
// Every read is best-effort by design: most of these values are optional, and
// the registry is full of entries carrying three of them. A missing value is the
// zero value, which is exactly what the rules in keepSoftware expect.
func readUninstallEntry(key registry.Key) rawSoftware {
	e := rawSoftware{}
	e.DisplayName, _, _ = key.GetStringValue("DisplayName")
	e.DisplayVersion, _, _ = key.GetStringValue("DisplayVersion")
	e.Publisher, _, _ = key.GetStringValue("Publisher")
	e.InstallDate, _, _ = key.GetStringValue("InstallDate")
	e.InstallLocation, _, _ = key.GetStringValue("InstallLocation")
	e.ReleaseType, _, _ = key.GetStringValue("ReleaseType")
	e.ParentKeyName, _, _ = key.GetStringValue("ParentKeyName")
	e.SystemComponent, _, _ = key.GetIntegerValue("SystemComponent")
	return e
}
