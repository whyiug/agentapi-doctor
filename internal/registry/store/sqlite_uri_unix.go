//go:build !windows

package store

import "net/url"

func validateSQLiteLocalPath(string) error { return nil }

func sqliteFileURL(filename string) url.URL {
	return url.URL{Scheme: "file", Path: filename}
}
