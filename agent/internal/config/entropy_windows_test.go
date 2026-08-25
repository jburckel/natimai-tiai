// Real-DPAPI behaviour of the entropy scheme — Windows only, since the
// non-Windows dpapi is a pass-through that ignores entropy entirely.
package config

import (
	"encoding/base64"
	"os"
	"testing"

	"tiai/agent/internal/dpapi"
)

// A token written before entropy existed must still load, and loading it must
// re-protect it under the entropy so the blob any local user can unprotect
// disappears from disk.
func TestLegacyTokenMigratesToEntropy(t *testing.T) {
	dir := t.TempDir()

	blob, err := dpapi.Protect([]byte("legacy-token"), nil)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(blob)
	if err := os.WriteFile(tokenPath(dir), []byte(encoded), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tok, err := LoadToken(dir)
	if err != nil || tok != "legacy-token" {
		t.Fatalf("legacy token must load: got %q err=%v", tok, err)
	}

	// The rewritten blob must now demand the entropy.
	raw, err := os.ReadFile(tokenPath(dir))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	rewritten, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err := dpapi.Unprotect(rewritten, nil); err == nil {
		t.Error("re-protected blob must not decrypt without the entropy")
	}
	if plain, err := dpapi.Unprotect(rewritten, readEntropy()); err != nil || string(plain) != "legacy-token" {
		t.Errorf("re-protected blob must decrypt with the entropy: %q err=%v", plain, err)
	}
}

// A lost entropy (deleted registry key, re-imaged system) must cost a
// re-enrollment, never a service that fails to start: LoadToken degrades to
// "no token stored".
func TestLostEntropyDegradesToReenroll(t *testing.T) {
	dir := t.TempDir()
	if err := SaveToken(dir, "secret-token-123"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	origRead, origEnsure := readEntropy, ensureEntropy
	t.Cleanup(func() { readEntropy, ensureEntropy = origRead, origEnsure })
	other := []byte("a-different-entropy-value-here!!")
	readEntropy = func() []byte { return other }
	ensureEntropy = func() []byte { return other }

	tok, err := LoadToken(dir)
	if err != nil {
		t.Fatalf("LoadToken must not fail on an undecryptable token: %v", err)
	}
	if tok != "" {
		t.Errorf("undecryptable token must read as absent, got %q", tok)
	}
}
