package collector

import "testing"

// The four rules are what make this list match "Applications et
// fonctionnalités". That match is the point: an administrator will compare the
// two, and every entry present here and absent there is a question to answer.
func TestKeepSoftwareMatchesWhatWindowsShows(t *testing.T) {
	cases := []struct {
		name  string
		entry rawSoftware
		keep  bool
	}{
		{"a program", rawSoftware{DisplayName: "7-Zip 24.09 (x64)"}, true},
		// The registry is full of these: leftovers, placeholders, MSI fragments.
		{"no display name", rawSoftware{DisplayVersion: "1.0"}, false},
		{"blank display name", rawSoftware{DisplayName: "   "}, false},
		// The publisher asking not to be listed.
		{"system component", rawSoftware{DisplayName: "Runtime", SystemComponent: 1}, false},
		{"system component zero", rawSoftware{DisplayName: "Runtime", SystemComponent: 0}, true},
		// A patch, which has its own module in this product. Listing KB entries
		// among the programs would bury the programs.
		{"security update", rawSoftware{DisplayName: "KB5063878", ReleaseType: "Security Update"}, false},
		{"update rollup", rawSoftware{DisplayName: "Rollup", ReleaseType: "Update Rollup"}, false},
		{"hotfix", rawSoftware{DisplayName: "Hotfix", ReleaseType: "Hotfix"}, false},
		// Case and spacing come from whatever installer wrote them.
		{"messy release type", rawSoftware{DisplayName: "X", ReleaseType: " SECURITY UPDATE "}, false},
		// A component of an entry already listed: an Office language pack.
		{"child entry", rawSoftware{DisplayName: "Pack FR", ParentKeyName: "Office"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := keepSoftware(c.entry); got != c.keep {
				t.Errorf("keepSoftware(%+v) = %v, want %v", c.entry, got, c.keep)
			}
		})
	}
}

func TestRegistryInstallDate(t *testing.T) {
	if got := registryInstallDate("20250601"); got != "2025-06-01" {
		t.Errorf("got %q, want 2025-06-01", got)
	}
	// An install date is a nicety. Guessing at a day/month order would put half
	// a parc's dates six months out, so anything unparseable is dropped.
	for _, bad := range []string{"", "01/06/2025", "2025-06-01", "abcdefgh", "20251301"} {
		if got := registryInstallDate(bad); got != "" {
			t.Errorf("registryInstallDate(%q) = %q, want empty", bad, got)
		}
	}
}

func TestBuildSoftwareStampsArchAndSource(t *testing.T) {
	got := buildSoftware([]rawSoftware{
		{DisplayName: "7-Zip", DisplayVersion: "24.09", Publisher: "Igor Pavlov",
			InstallDate: "20250601", InstallLocation: `C:\Program Files\7-Zip`},
		{DisplayName: "", DisplayVersion: "1.0"},
	}, softwareSourceWOW)
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].Arch != "x86" || got[0].Source != softwareSourceWOW {
		t.Errorf("the 32-bit hive must stamp x86, got %q / %q", got[0].Arch, got[0].Source)
	}
	if got[0].InstallDate != "2025-06-01" {
		t.Errorf("install date %q", got[0].InstallDate)
	}
}

// Version and publisher travel as "" and never as absent: they are two thirds
// of the catalogue's unique key server-side, and Postgres treats NULLs as
// distinct — a nullable publisher would let one unpublished program accumulate
// a catalogue row per machine.
func TestBuildSoftwareKeepsEmptyIdentityFields(t *testing.T) {
	got := buildSoftware([]rawSoftware{{DisplayName: "Outil maison"}}, softwareSourceHKLM)
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].Version != "" || got[0].Publisher != "" {
		t.Errorf("expected empty strings, got %+v", got[0])
	}
}

// The same program can genuinely appear in both hives. The server keys on the
// triple, so a duplicate would be an upsert conflict rather than a second row —
// collapsed here so the count the agent logs and the count the console shows
// are the same number.
func TestDedupeSoftware(t *testing.T) {
	entries := buildSoftware([]rawSoftware{
		{DisplayName: "Tool", DisplayVersion: "1.0", Publisher: "Acme"},
	}, softwareSourceHKLM)
	entries = append(entries, buildSoftware([]rawSoftware{
		{DisplayName: "Tool", DisplayVersion: "1.0", Publisher: "Acme"},
		{DisplayName: "Tool", DisplayVersion: "2.0", Publisher: "Acme"},
	}, softwareSourceWOW)...)

	got := dedupeSoftware(entries)
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct entries, got %d: %+v", len(got), got)
	}
	// First hive wins, which is the 64-bit one — the arch that is right when a
	// program really is installed twice.
	if got[0].Source != softwareSourceHKLM {
		t.Errorf("the first occurrence must win, got %q", got[0].Source)
	}
}
