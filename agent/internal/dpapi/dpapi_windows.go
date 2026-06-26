// Package dpapi wraps the Windows Data Protection API (DPAPI) used to encrypt
// the per-machine token at rest (plan §2.4). Machine scope
// (CRYPTPROTECT_LOCAL_MACHINE) is used so the LocalSystem service can decrypt
// regardless of the interactive user.
package dpapi

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	crypt32                = windows.NewLazySystemDLL("crypt32.dll")
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32.NewProc("LocalFree")
)

// CRYPTPROTECT_LOCAL_MACHINE: any principal on this machine can unprotect.
const cryptProtectLocalMachine = 0x4

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) dataBlob {
	if len(d) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(d)), pbData: &d[0]}
}

func (b *dataBlob) bytes() []byte {
	out := make([]byte, b.cbData)
	if b.cbData > 0 {
		copy(out, unsafe.Slice(b.pbData, b.cbData))
	}
	return out
}

// Protect encrypts data with the machine DPAPI key.
func Protect(data []byte) ([]byte, error) {
	in := newBlob(data)
	var out dataBlob
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0,
		cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData))) //nolint:errcheck
	return out.bytes(), nil
}

// Unprotect decrypts data produced by Protect on the same machine.
func Unprotect(data []byte) ([]byte, error) {
	in := newBlob(data)
	var out dataBlob
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0,
		cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData))) //nolint:errcheck
	return out.bytes(), nil
}
