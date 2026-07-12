//go:build !windows

package cas

import "os"

// pinFileIdentity is a no-op on Unix because os.Lstat records the stable
// device/inode identity in the returned FileInfo.
func pinFileIdentity(info os.FileInfo) bool {
	return info != nil
}
