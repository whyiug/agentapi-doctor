package store

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"
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
	volume := filepath.ToSlash(filepath.VolumeName(filename))
	if volume != "" && !strings.HasPrefix(slashPath, "/") {
		// A drive letter belongs in the path, not in the URI authority where
		// net/url would parse its colon as a port separator.
		slashPath = "/" + slashPath
	}
	return url.URL{Scheme: "file", Path: slashPath}
}
