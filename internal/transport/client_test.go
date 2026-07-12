package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type staticResolver []netip.Addr

func (resolver staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), resolver...), nil
}

func TestLocalAuthorizedOriginAndResponseLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/large" {
			_, _ = writer.Write([]byte(strings.Repeat("x", 32)))
			return
		}
		writer.Header().Set("X-Test", "yes")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	client, err := New(Policy{AllowedOrigin: server.URL, Mode: NetworkLocalTarget, AllowPlainHTTP: true, MaxResponseBytes: 16, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(context.Background(), http.MethodPost, "/v1/test", http.Header{"Content-Type": []string{"application/json"}}, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || string(response.Body) != `{"ok":true}` || response.Header.Get("X-Test") != "yes" {
		t.Fatalf("response=%#v", response)
	}
	if _, err := client.Do(context.Background(), http.MethodGet, "/large", nil, nil); !errors.Is(err, ErrBodyLimit) {
		t.Fatalf("expected limit, got %v", err)
	}
}

func TestPublicRunnerBlocksLoopbackBeforeDial(t *testing.T) {
	client, err := New(Policy{AllowedOrigin: "http://blocked.invalid:8080", Mode: NetworkPublicRunner, AllowPlainHTTP: true, Resolver: staticResolver{netip.MustParseAddr("127.0.0.1")}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(context.Background(), http.MethodGet, "/", nil, nil)
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected blocked address, got %v", err)
	}
}

func TestPublicRunnerRejectsIANARegisteredSpecialUseAddresses(t *testing.T) {
	tests := []struct {
		address string
		public  bool
	}{
		{address: "8.8.8.8", public: true},
		{address: "2606:4700:4700::1111", public: true},
		{address: "100.64.0.1"},
		{address: "192.0.2.1"},
		{address: "198.18.0.1"},
		{address: "198.51.100.1"},
		{address: "203.0.113.1"},
		{address: "::ffff:192.0.2.1"},
		{address: "64:ff9b:1::1"},
		{address: "100:0:0:1::1"},
		{address: "2001:db8::1"},
		{address: "3fff::1"},
		{address: "5f00::1"},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := isPublic(netip.MustParseAddr(test.address)); got != test.public {
				t.Fatalf("isPublic(%s) = %v, want %v", test.address, got, test.public)
			}
		})
	}
}

func TestAbsoluteOrCrossOriginRequestRejected(t *testing.T) {
	client, err := New(Policy{AllowedOrigin: "https://api.example.test", Mode: NetworkLocalTarget})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"https://evil.test/x", "relative", "/ok#fragment"} {
		if _, err := client.Do(context.Background(), http.MethodGet, path, nil, nil); err == nil {
			t.Fatalf("expected rejection for %q", path)
		}
	}
}

func TestRedirectPolicyDoesNotFollow(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Redirect(writer, &http.Request{}, target.URL, http.StatusFound)
	}))
	defer source.Close()
	client, err := New(Policy{AllowedOrigin: source.URL, Mode: NetworkLocalTarget, AllowPlainHTTP: true, Redirects: RedirectNone, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), http.MethodGet, "/", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusFound || reached {
		t.Fatalf("status=%d reached=%v", response.StatusCode, reached)
	}
}

func TestPlainHTTPRequiresExplicitApproval(t *testing.T) {
	if _, err := New(Policy{AllowedOrigin: "http://127.0.0.1:1234"}); err == nil {
		t.Fatal("expected plain HTTP rejection")
	}
}

func TestTLSServerNameCannotEscapeOrigin(t *testing.T) {
	if _, err := New(Policy{AllowedOrigin: "https://api.example.test", TLSConfig: &TLSConfig{ServerName: "other.example.test"}}); err == nil {
		t.Fatal("accepted TLS identity for a different origin")
	}
}
