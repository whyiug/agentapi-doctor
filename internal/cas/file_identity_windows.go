//go:build windows

package cas

import "os"

// Windows os.Lstat defers loading a file's volume serial number and file
// index until os.SameFile needs them. Pin that handle-derived identity while
// the path is known to name the inspected object; otherwise a later path
// replacement can make the old FileInfo resolve to the replacement object.
func pinFileIdentity(info os.FileInfo) bool {
	return info != nil && os.SameFile(info, info)
}
