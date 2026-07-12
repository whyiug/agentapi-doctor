package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

type staticResolver []netip.Addr

func (resolver staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), resolver...), nil
}

type countingResolver struct {
	addresses []netip.Addr
	calls     int
}

func (resolver *countingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	resolver.calls++
	return append([]netip.Addr(nil), resolver.addresses...), nil
}

type countingDialer struct {
	calls int
}

func (dialer *countingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	dialer.calls++
	return nil, errors.New("unexpected dial")
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

func TestForbiddenLiteralsAreRejectedWithoutResolveOrDial(t *testing.T) {
	tests := []string{
		"0.0.0.0",
		"::",
		"224.0.0.1",
		"ff02::1",
		"169.254.1.1",
		"fe80::1",
		"169.254.169.254",
		"100.100.100.200",
		"fd00:ec2::254",
		"fd00:ec2::254%eth0",
	}
	for _, mode := range []NetworkMode{NetworkLocalTarget, NetworkPublicRunner} {
		for _, address := range tests {
			t.Run(string(mode)+"/"+address, func(t *testing.T) {
				literal := netip.MustParseAddr(address)
				urlHost := strings.ReplaceAll(net.JoinHostPort(literal.String(), "8080"), "%", "%25")
				origin, err := url.Parse("http://" + urlHost)
				if err != nil {
					t.Fatal(err)
				}
				resolver := &countingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
				dialer := &countingDialer{}
				dial := originDialer(origin, mode, resolver, dialer)

				_, err = dial(context.Background(), "tcp", canonicalHost(origin))
				if !errors.Is(err, ErrBlockedAddress) {
					t.Fatalf("expected blocked literal, got %v", err)
				}
				if resolver.calls != 0 || dialer.calls != 0 {
					t.Fatalf("forbidden literal reached resolver or dialer: resolve=%d dial=%d", resolver.calls, dialer.calls)
				}
			})
		}
	}
}

func TestForbiddenDNSAnswersAreRejectedWithoutDial(t *testing.T) {
	tests := []struct {
		name    string
		address netip.Addr
	}{
		{name: "invalid", address: netip.Addr{}},
		{name: "ipv4 unspecified", address: netip.MustParseAddr("0.0.0.0")},
		{name: "ipv6 unspecified", address: netip.MustParseAddr("::")},
		{name: "ipv4 multicast", address: netip.MustParseAddr("224.0.0.1")},
		{name: "ipv6 multicast", address: netip.MustParseAddr("ff02::1")},
		{name: "ipv4 link local", address: netip.MustParseAddr("169.254.1.1")},
		{name: "ipv6 link local", address: netip.MustParseAddr("fe80::1")},
		{name: "aws metadata", address: netip.MustParseAddr("169.254.169.254")},
		{name: "alibaba metadata", address: netip.MustParseAddr("100.100.100.200")},
		{name: "ec2 ipv6 metadata", address: netip.MustParseAddr("fd00:ec2::254")},
		{name: "mapped metadata", address: netip.MustParseAddr("::ffff:100.100.100.200")},
	}
	for _, mode := range []NetworkMode{NetworkLocalTarget, NetworkPublicRunner} {
		for _, test := range tests {
			t.Run(string(mode)+"/"+test.name, func(t *testing.T) {
				origin, err := url.Parse("http://metadata.example.test:8080")
				if err != nil {
					t.Fatal(err)
				}
				resolver := &countingResolver{addresses: []netip.Addr{test.address}}
				dialer := &countingDialer{}
				dial := originDialer(origin, mode, resolver, dialer)

				_, err = dial(context.Background(), "tcp", "metadata.example.test:8080")
				if !errors.Is(err, ErrBlockedAddress) {
					t.Fatalf("expected blocked DNS answer, got %v", err)
				}
				if resolver.calls != 1 || dialer.calls != 0 {
					t.Fatalf("forbidden DNS answer reached unexpected boundary: resolve=%d dial=%d", resolver.calls, dialer.calls)
				}
			})
		}
	}
}

func TestMixedDNSAnswerWithForbiddenAddressDoesNotDial(t *testing.T) {
	origin, err := url.Parse("http://metadata.example.test:8080")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &countingResolver{addresses: []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("100.100.100.200"),
	}}
	dialer := &countingDialer{}
	dial := originDialer(origin, NetworkLocalTarget, resolver, dialer)

	_, err = dial(context.Background(), "tcp", "metadata.example.test:8080")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected mixed DNS answer to fail closed, got %v", err)
	}
	if resolver.calls != 1 || dialer.calls != 0 {
		t.Fatalf("mixed DNS answer reached unexpected boundary: resolve=%d dial=%d", resolver.calls, dialer.calls)
	}
}

func TestAllowedLocalDNSAnswerReachesDialer(t *testing.T) {
	origin, err := url.Parse("http://fixture.example.test:8080")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &countingResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	dialer := &countingDialer{}
	dial := originDialer(origin, NetworkLocalTarget, resolver, dialer)

	_, err = dial(context.Background(), "tcp", "fixture.example.test:8080")
	if err == nil || err.Error() != "unexpected dial" {
		t.Fatalf("expected test dialer error, got %v", err)
	}
	if resolver.calls != 1 || dialer.calls != 1 {
		t.Fatalf("allowed DNS answer did not reach dialer exactly once: resolve=%d dial=%d", resolver.calls, dialer.calls)
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
