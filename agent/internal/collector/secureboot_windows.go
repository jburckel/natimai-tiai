package collector

import "golang.org/x/sys/windows/registry"

// readSecureBoot reports whether UEFI Secure Boot is enabled, and whether the
// question could be answered at all.
//
// Read from the registry rather than from `Confirm-SecureBootUEFI`: the cmdlet
// is PowerShell — a process launch this agent otherwise avoids — and it *throws*
// on a BIOS (non-UEFI) machine rather than answering "no". The value below is
// simply absent there, which is the honest answer: a machine with no UEFI has no
// Secure Boot to have off.
func readSecureBoot() (bool, bool) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\SecureBoot\State`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return false, false
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("UEFISecureBootEnabled")
	if err != nil {
		return false, false
	}
	return value == 1, true
}
