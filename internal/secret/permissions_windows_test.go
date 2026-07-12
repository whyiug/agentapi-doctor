package secret

import (
	"io/fs"
	"strings"
	"testing"
)

func TestWindowsFileSecretPermissionsFailClosed(t *testing.T) {
	err := validatePrivateFilePermissions(`C:\synthetic-token`, fs.FileMode(0o666))
	if err == nil || !strings.Contains(err.Error(), "unsupported on Windows") {
		t.Fatalf("Windows file secret did not fail closed: %v", err)
	}
}
