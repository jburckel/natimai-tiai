// Package sysinfo reports the host attributes the server stores alongside a
// machine: hostname, AD domain, and OS version. These are plain attributes
// (plan §2.3) — they may change without affecting the machine's identity.
package sysinfo

import "os"

// Info is the host descriptor sent on enroll and heartbeat.
type Info struct {
	Hostname  string
	Domain    string
	OSVersion string
}

// Collect reads the current host attributes. Best-effort: missing values are
// returned empty rather than failing.
func Collect() Info {
	h, _ := os.Hostname()
	return Info{
		Hostname:  h,
		Domain:    domain(),
		OSVersion: osVersion(),
	}
}
