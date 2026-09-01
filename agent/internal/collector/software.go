package collector

import (
	"strings"
	"time"

	"tiai/agent/internal/models"
)

// Installed software, read from the registry's Uninstall keys.
//
// **Never Win32_Product.** Enumerating that WMI class makes the Windows
// Installer run a consistency check on every installed package: the query takes
// minutes and writes an MsiInstaller event into the Application log of every
// machine, every time. On a parc of a thousand postes polled daily that is
// indefensible, and it is why every inventory tool of the last twenty years —
// GLPI's agent included — reads the registry instead. The registry read below
// is a few dozen milliseconds and has no side effect at all.
//
// Two hives are walked, and forgetting the second is the classic mistake:
//
//	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall            (64-bit)
//	HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall (32-bit)
//
// A 64-bit Windows keeps 32-bit programs — which is a good third of what a parc
// actually runs — in the second one alone.
//
// Deliberately *not* read, and it is a privacy decision as much as a technical
// one (dev/plan-inventaire.md §7): the per-user hives (HKU\<SID>\…) and the
// Store packages. Both would attribute software to a named person rather than
// to a machine, and neither is needed to answer "which postes still run this".

// softwareSourceHKLM and softwareSourceWOW name the hive an entry came from.
// Stored server-side because "why does this 32-bit program show up twice" is
// answered by it.
const (
	softwareSourceHKLM = "registry"
	softwareSourceWOW  = "registry_wow64"
)

// archFor maps a hive to the architecture of the programs it holds.
var archFor = map[string]string{softwareSourceHKLM: "x64", softwareSourceWOW: "x86"}

// rawSoftware is one Uninstall subkey, with the values the filtering needs.
// Kept out of the //go:build windows file so the rules below stay testable.
type rawSoftware struct {
	DisplayName     string
	DisplayVersion  string
	Publisher       string
	InstallDate     string // "20250601", when present at all
	InstallLocation string
	// SystemComponent = 1 hides an entry from "Applications et fonctionnalités".
	SystemComponent uint64
	// "Security Update", "Update Rollup", "Hotfix" — a patch, not a program.
	ReleaseType string
	// Set on an entry that is a component of another one already listed.
	ParentKeyName string
}

// keepSoftware applies the four rules that make this list match what a user sees
// in "Applications et fonctionnalités".
//
// That match is the point: an administrator will compare the two, and every
// entry present here and absent there is a question to answer. Windows' own
// panel hides the same four things, for the same reasons.
func keepSoftware(e rawSoftware) bool {
	if strings.TrimSpace(e.DisplayName) == "" {
		// An Uninstall key with no display name is a leftover, a placeholder or a
		// component. The registry is full of them.
		return false
	}
	if e.SystemComponent == 1 {
		// The publisher asking not to be listed: runtimes, redistributable
		// fragments, driver packages shipped with an application.
		return false
	}
	switch strings.TrimSpace(strings.ToLower(e.ReleaseType)) {
	case "security update", "update rollup", "hotfix", "servicepack", "service pack":
		// A patch, which has its own module in this product. Listing KB entries
		// among the programs would bury the programs.
		return false
	}
	// A component of an entry already in the list: an Office language pack, an
	// MSI feature. Counting it as a program would inflate every catalogue figure.
	return strings.TrimSpace(e.ParentKeyName) == ""
}

// registryInstallDate turns the "20250601" the registry holds into the
// "2025-06-01" the server's DATE column takes.
//
// Returns "" for anything else, and there is plenty of anything else: the value
// is optional, some installers write a localised "01/06/2025", and some write
// nothing at all. An install date is a nicety — dropping an unparseable one
// costs nothing, while guessing at a day/month order would put half the parc's
// dates six months out.
func registryInstallDate(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) != 8 {
		return ""
	}
	t, err := time.Parse("20060102", s)
	if err != nil {
		return ""
	}
	return t.Format("2006-01-02")
}

// buildSoftware maps and filters the entries of one hive.
func buildSoftware(entries []rawSoftware, source string) []models.Software {
	out := make([]models.Software, 0, len(entries))
	for _, e := range entries {
		if !keepSoftware(e) {
			continue
		}
		out = append(out, models.Software{
			Name: strings.TrimSpace(e.DisplayName),
			// Version and publisher are never nil and never omitted: together
			// with the name they are the catalogue's unique key server-side, and
			// Postgres treats NULLs as distinct — a missing publisher has to be
			// "" or one unpublished program grows a catalogue row per machine.
			Version:         strings.TrimSpace(e.DisplayVersion),
			Publisher:       strings.TrimSpace(e.Publisher),
			InstallDate:     registryInstallDate(e.InstallDate),
			Arch:            archFor[source],
			Source:          source,
			InstallLocation: strings.TrimSpace(e.InstallLocation),
		})
	}
	return out
}

// dedupeSoftware collapses entries that share a name, version and publisher.
//
// The same program can genuinely appear in both hives — an installer that wrote
// to the 64-bit view and a 32-bit repair that wrote to the other — and the
// server keys on exactly this triple, so a duplicate would be an upsert
// conflict rather than a second row. Collapsed here so the count the agent
// reports and the count the console shows are the same number.
func dedupeSoftware(entries []models.Software) []models.Software {
	seen := make(map[[3]string]struct{}, len(entries))
	out := make([]models.Software, 0, len(entries))
	for _, e := range entries {
		key := [3]string{e.Name, e.Version, e.Publisher}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	return out
}
