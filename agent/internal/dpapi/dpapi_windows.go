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

// Protect encrypts data with the machine DPAPI key. The optional entropy is a
// second secret mixed into the key derivation: machine scope alone lets *any*
// local principal decrypt, so callers pass a blob that standard users cannot
// read (cf. config: the entropy lives under an ACL'd registry key). nil keeps
// the historical behaviour.
func Protect(data, entropy []byte) ([]byte, error) {
	in := newBlob(data)
	var out dataBlob
	// A nil *dataBlob converts to a 0 uintptr, which is how the API spells
	// "no entropy". The conversion happens inside the Call expression so the
	// blob stays pinned for the syscall's duration.
	var pEntropy *dataBlob
	if len(entropy) > 0 {
		b := newBlob(entropy)
		pEntropy = &b
	}
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		uintptr(unsafe.Pointer(pEntropy)),
		0, 0,
		cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData))) //nolint:errcheck
	return out.bytes(), nil
}

// Unprotect decrypts data produced by Protect on the same machine, with the
// same entropy it was protected under (nil for none).
func Unprotect(data, entropy []byte) ([]byte, error) {
	in := newBlob(data)
	var out dataBlob
	var pEntropy *dataBlob
	if len(entropy) > 0 {
		b := newBlob(entropy)
		pEntropy = &b
	}
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		uintptr(unsafe.Pointer(pEntropy)),
		0, 0,
		cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData))) //nolint:errcheck
	return out.bytes(), nil
}
