//go:build !windows

package secret

import (
	"fmt"
	"io/fs"
)

func validatePrivateFilePermissions(_ string, mode fs.FileMode) error {
	if mode.Perm()&0o077 != 0 {
		return fmt.Errorf("secret file permissions %04o expose group or other bits", mode.Perm())
	}
	return nil
}
