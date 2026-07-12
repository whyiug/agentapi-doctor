//go:build !windows

package secret

import (
	"io/fs"
	"testing"
)

func TestPrivateFilePermissionsRemainStrictOnPOSIX(t *testing.T) {
	for _, mode := range []fs.FileMode{0o600, 0o400, 0} {
		if err := validatePrivateFilePermissions("unused", mode); err != nil {
			t.Fatalf("private mode %04o: %v", mode, err)
		}
	}
	for _, mode := range []fs.FileMode{0o640, 0o604, 0o666, 0o777} {
		if err := validatePrivateFilePermissions("unused", mode); err == nil {
			t.Fatalf("broad mode %04o was accepted", mode)
		}
	}
}
