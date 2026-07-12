//go:build !windows

package cas

import (
	"errors"
	"os"
)

func syncDirectoryPlatform(path string) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return errors.New("directory sync path must be a non-symlink directory")
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	opened, err := directory.Stat()
	if err != nil {
		return err
	}
	if !opened.IsDir() || !os.SameFile(before, opened) {
		return errors.New("directory changed before sync")
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.IsDir() || !os.SameFile(opened, after) {
		return errors.New("directory changed during sync")
	}
	return nil
}
