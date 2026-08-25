package agent

import (
	"fmt"
	"testing"
	"time"

	"tiai/agent/internal/api"
)

func TestNextBackoffDoublesAndCaps(t *testing.T) {
	base := 60 * time.Second
	max := 300 * time.Second

	got := nextBackoff(base, max)
	if got != 120*time.Second {
		t.Errorf("first backoff = %s, want 2m", got)
	}
	got = nextBackoff(got, max)
	if got != 240*time.Second {
		t.Errorf("second backoff = %s, want 4m", got)
	}
	// 240 * 2 = 480 > 300 → capped.
	got = nextBackoff(got, max)
	if got != max {
		t.Errorf("third backoff = %s, want cap %s", got, max)
	}
	// Stays capped.
	if got = nextBackoff(got, max); got != max {
		t.Errorf("backoff should stay at cap, got %s", got)
	}
}

// The 401 detection is what turns a revocation into a re-enrollment instead of
// an endless 401 loop, so it must see the status through the client's wrapping
// — and must NOT fire on anything else (a 403 is "stay away", not "retry").
func TestIsUnauthorized(t *testing.T) {
	wrapped := fmt.Errorf("POST /api/v1/agent/heartbeat: %w",
		&api.StatusError{StatusCode: 401, Body: "revoked"})
	if !isUnauthorized(wrapped) {
		t.Error("wrapped 401 not detected")
	}
	forbidden := fmt.Errorf("POST /api/v1/agent/enroll: %w",
		&api.StatusError{StatusCode: 403, Body: "machine.enrollment.revoked"})
	if isUnauthorized(forbidden) {
		t.Error("403 must not count as unauthorized")
	}
	if isUnauthorized(fmt.Errorf("dial tcp: connection refused")) {
		t.Error("transport error must not count as unauthorized")
	}
	if isUnauthorized(nil) {
		t.Error("nil error must not count as unauthorized")
	}
}
