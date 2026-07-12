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
	dsn := sqliteDSN(drivePath)
	if want := `file:C:/Users/runner%20admin/registry.db?_txlock=immediate`; dsn != want {
		t.Fatalf("SQLite DSN = %q, want %q", dsn, want)
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "file" || parsed.Host != "" || parsed.Opaque != `C:/Users/runner%20admin/registry.db` || parsed.Query().Get("_txlock") != "immediate" {
		t.Fatalf("parsed URI = %#v", parsed)
	}
	for _, path := range []string{`\\server\share\registry.db`, `\\?\C:\registry.db`, `\registry.db`} {
		if err := validateSQLiteLocalPath(path); err == nil {
			t.Fatalf("accepted non-local Windows path %q", path)
		}
	}
}
