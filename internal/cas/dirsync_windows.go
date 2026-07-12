//go:build windows

package cas

import (
	"errors"
	"os"
)

// Windows does not provide a portable directory fsync through os.File.Sync.
// Validate a stable non-symlink directory identity and rely on atomic link and
// rename semantics plus the already-synced file handle.
func syncDirectoryPlatform(path string) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return errors.New("directory sync path must be a non-symlink directory")
	}
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.IsDir() || !os.SameFile(before, after) {
		return errors.New("directory changed during sync fallback")
	}
	return nil
}
