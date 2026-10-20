//go:build windows

package agent

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows DPAPI protection for the credential store (user scope: only the
// account that runs the agent can open a value). This is the one file allowed
// to import unsafe (internal/archtest allows exactly this path): the DPAPI
// output buffer is native memory that can only be read and freed through it.
//
// It was written and cross-compiled (GOOS=windows go vet) but not run on a
// Windows host in this change; it is deliberately minimal.

// dpapiEntropy binds a protected value to this application: another program
// running as the same user cannot open it by calling CryptUnprotectData
// without the entropy.
var dpapiEntropy = []byte("tessera-directory-agent/v1")

func blobOf(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// take copies and wipes a DPAPI output blob, then frees it.
func take(out *windows.DataBlob) []byte {
	if out.Data == nil {
		return nil
	}
	native := unsafe.Slice(out.Data, out.Size)
	res := append([]byte(nil), native...)
	clear(native)
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return res
}

func dpapiProtect(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("agent: nothing to protect")
	}
	in, ent := blobOf(b), blobOf(dpapiEntropy)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return take(&out), nil
}

func dpapiUnprotect(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("agent: nothing to unprotect")
	}
	in, ent := blobOf(b), blobOf(dpapiEntropy)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return take(&out), nil
}
