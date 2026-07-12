package secret

import (
	"errors"
	"io/fs"
)

// Go's synthesized POSIX mode bits cannot prove that a Windows DACL is private.
// Until the resolver has an audited DACL implementation, reject file:// rather
// than silently accepting a file readable by another principal.
func validatePrivateFilePermissions(string, fs.FileMode) error {
	return errors.New("file secret access validation is unsupported on Windows; use env://")
}
