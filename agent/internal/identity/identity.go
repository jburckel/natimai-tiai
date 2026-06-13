// Package identity resolves a machine's stable identity and fingerprint.
//
// Strategy (plan §2.3), tuned for physical machines re-imaged WITHOUT Sysprep
// (where MachineGuid is duplicated across clones):
//
//  1. Anchor = SMBIOS/System UUID (Win32_ComputerSystemProduct.UUID), unique
//     per motherboard and stable across OS re-image / rename / domain change.
//  2. If the SMBIOS UUID is missing or in the known-bad denylist, fall back to
//     a random UUID generated once and persisted under ProgramData\Tiai.
//  3. The fingerprint (MachineGuid + SMBIOS UUID + TPM EK hash) is reported
//     alongside so the server can flag suspicious changes ("needs verification").
//
// The platform reads (WMI/registry/TBS) are stubbed here to keep the skeleton
// buildable on any OS; port the real implementations from the Windows agent.
package identity

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tiai/agent/internal/models"
)

// invalidSMBIOSUUIDs lists values that must never be trusted as an identity:
// null, all-F, and notorious duplicated OEM constants.
var invalidSMBIOSUUIDs = map[string]bool{
	"00000000-0000-0000-0000-000000000000": true,
	"ffffffff-ffff-ffff-ffff-ffffffffffff": true,
	"03000200-0400-0500-0006-000700080009": true, // common whitebox/clone constant
}

// Identity is the resolved stable id plus the reported fingerprint.
type Identity struct {
	MachineUUID string
	Fingerprint models.Fingerprint
}

// Resolve computes the machine identity, persisting a fallback UUID in cfgDir
// when no trustworthy hardware anchor is available. A non-empty override
// (from config) takes precedence over the resolved anchor.
func Resolve(cfgDir, override string) (Identity, error) {
	fp := models.Fingerprint{
		MachineGUID: readMachineGUID(),
		SMBIOSUUID:  readSMBIOSUUID(),
		TPMEKHash:   readTPMEKHash(),
	}

	if ov := normalize(override); ov != "" {
		return Identity{MachineUUID: ov, Fingerprint: fp}, nil
	}

	if uuid := normalize(fp.SMBIOSUUID); uuid != "" && !invalidSMBIOSUUIDs[uuid] {
		return Identity{MachineUUID: uuid, Fingerprint: fp}, nil
	}

	// No trustworthy anchor → persisted, agent-generated UUID.
	uuid, err := persistedFallbackUUID(cfgDir)
	if err != nil {
		return Identity{}, err
	}
	return Identity{MachineUUID: uuid, Fingerprint: fp}, nil
}

func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// persistedFallbackUUID reads, or generates and stores, agent_id under cfgDir.
func persistedFallbackUUID(cfgDir string) (string, error) {
	path := filepath.Join(cfgDir, "agent_id")
	if data, err := os.ReadFile(path); err == nil {
		if id := normalize(string(data)); id != "" {
			return id, nil
		}
	}
	id, err := newUUIDv4()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(cfgDir, 0o750); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id), 0o640); err != nil {
		return "", err
	}
	return id, nil
}

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// --- Platform reads (stubs; port from natimai-windows-console) --------------

// readSMBIOSUUID returns Win32_ComputerSystemProduct.UUID via WMI on Windows.
func readSMBIOSUUID() string { return "" } // TODO(M1): WMI

// readMachineGUID returns HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid.
func readMachineGUID() string { return "" } // TODO(M1): registry

// readTPMEKHash returns a hash of the TPM 2.0 Endorsement Key public, if any.
func readTPMEKHash() string { return "" } // TODO(M2): TBS / Get-TpmEndorsementKeyInfo
