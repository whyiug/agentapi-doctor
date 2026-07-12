package store

import (
	"net/url"
	"testing"
)

func TestSQLiteWindowsDriveFileURIRejectsNonLocalPaths(t *testing.T) {
	drivePath := `C:\Users\runner admin\registry.db`
	if err := validateSQLiteLocalPath(drivePath); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(sqliteDSN(drivePath))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "file" || parsed.Host != "" || parsed.Path != `/C:/Users/runner admin/registry.db` || parsed.Query().Get("_txlock") != "immediate" {
		t.Fatalf("parsed URI = %#v", parsed)
	}
	for _, path := range []string{`\\server\share\registry.db`, `\\?\C:\registry.db`, `\registry.db`} {
		if err := validateSQLiteLocalPath(path); err == nil {
			t.Fatalf("accepted non-local Windows path %q", path)
		}
	}
}
