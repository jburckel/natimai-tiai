package identity

import (
	"os/exec"
	"strings"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/registry"
)

type win32ComputerSystemProduct struct {
	UUID string
}

// readSMBIOSUUID returns Win32_ComputerSystemProduct.UUID via WMI — the SMBIOS
// system UUID, the primary identity anchor (plan §2.3).
func readSMBIOSUUID() string {
	// Explicit class name: wmi.CreateQuery would derive it from the Go type
	// name (win32ComputerSystemProduct), which doesn't match the WMI class.
	var dst []win32ComputerSystemProduct
	if err := wmi.Query("SELECT UUID FROM Win32_ComputerSystemProduct", &dst); err != nil || len(dst) == 0 {
		return ""
	}
	return strings.TrimSpace(dst[0].UUID)
}

// readMachineGUID returns HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid.
// Reported as a fingerprint component only — it is duplicated across clones
// imaged without Sysprep, so it is never used as the identity.
func readMachineGUID() string {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// readTPMEKHash returns a hash of the TPM 2.0 Endorsement Key public, if a TPM
// is present. Best-effort and optional (plan §2.3: bonus fingerprint, never
// depended upon) — any failure yields "".
func readTPMEKHash() string {
	out, err := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-TpmEndorsementKeyInfo -ErrorAction SilentlyContinue).PublicKeyHash",
	).Output()
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(string(out)))
}
