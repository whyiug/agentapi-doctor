package matrix

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAssetsUseStrictCSPAndTypes(t *testing.T) {
	for _, test := range []struct{ path, contentType string }{{"/matrix/", "text/html"}, {"/matrix/app.js", "text/javascript"}, {"/matrix/style.css", "text/css"}} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		response := httptest.NewRecorder()
		Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), test.contentType) {
			t.Fatalf("%s status=%d type=%s", test.path, response.Code, response.Header().Get("Content-Type"))
		}
		csp := response.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "'unsafe-inline'") {
			t.Fatalf("unsafe CSP: %s", csp)
		}
	}
}
func TestJavaScriptUsesDOMTextBoundary(t *testing.T) {
	raw, err := assets.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, forbidden := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "document.write"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("unsafe sink %q", forbidden)
		}
	}
	if !strings.Contains(source, "textContent") {
		t.Fatal("missing safe text sink")
	}
	for _, required := range []string{"trust_labels", "freshness", "pack_version", `"project"`} {
		if !strings.Contains(source, required) {
			t.Fatalf("Matrix renderer does not consume observation field %q", required)
		}
	}
	for _, stale := range []string{`["subject", "namespace"]`, `["registry_derived", "trust", "label"]`, `["registry_derived", "freshness", "status"]`} {
		if strings.Contains(source, stale) {
			t.Fatalf("Matrix renderer still consumes stale observation shape %q", stale)
		}
	}
}
func TestUnknownAssetAndMutationRejected(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		request := httptest.NewRequest(method, "/matrix/", nil)
		response := httptest.NewRecorder()
		Handler().ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("method=%s status=%d", method, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/matrix/../secret", nil)
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d", response.Code)
	}
}
