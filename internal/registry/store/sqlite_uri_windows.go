package store

import (
	"errors"
	"net/url"
	"path/filepath"
)

func validateSQLiteLocalPath(filename string) error {
	volume := filepath.VolumeName(filename)
	if len(volume) != 2 || volume[1] != ':' || !isASCIILetter(volume[0]) {
		return errors.New("SQLite path must use a local Windows drive; UNC and device paths are not supported")
	}
	return nil
}

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func sqliteFileURL(filename string) url.URL {
	slashPath := filepath.ToSlash(filename)
	// SQLite's pure-Go VFS passes a URI path directly to os.OpenFile. The
	// conventional file:///C:/ form therefore becomes the invalid Windows path
	// /C:. Use SQLite's file:C:/... opaque form while still escaping spaces,
	// percent signs, query delimiters, and fragments as path data.
	escapedPath := (&url.URL{Path: slashPath}).EscapedPath()
	return url.URL{Scheme: "file", Opaque: escapedPath}
}
