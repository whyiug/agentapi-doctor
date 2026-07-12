// Package transport implements an origin-bound HTTP transport for authorized
// endpoint testing. It does not discover or scan targets.
package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultMaxRequestBytes  int64 = 16 << 20
	DefaultMaxResponseBytes int64 = 64 << 20
)

type NetworkMode string

const (
	// NetworkLocalTarget runs on the user's machine and permits the addresses
	// of one explicitly configured, exact-origin target. The target itself may
	// be loopback, private-network, or public; "local" describes the runner.
	NetworkLocalTarget NetworkMode = "local_target"
	// NetworkPublicRunner rejects non-public, link-local, multicast, and
	// unspecified addresses. It is intended for project-operated runners.
	NetworkPublicRunner NetworkMode = "public_runner"
)

type RedirectPolicy string

const (
	RedirectNone       RedirectPolicy = "none"
	RedirectSameOrigin RedirectPolicy = "same_origin"
)

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Policy struct {
	AllowedOrigin    string
	Mode             NetworkMode
	Redirects        RedirectPolicy
	MaxRedirects     int
	AllowPlainHTTP   bool
	MaxRequestBytes  int64
	MaxResponseBytes int64
	Timeout          time.Duration
	Resolver         Resolver
	Dialer           *net.Dialer
	TLSConfig        *TLSConfig
}

// TLSConfig is the small stable subset callers may tune. InsecureSkipVerify
// is intentionally absent.
type TLSConfig struct {
	RootCAsFile string
	ServerName  string
}

type Client struct {
	origin           *url.URL
	client           *http.Client
	maxRequestBytes  int64
	maxResponseBytes int64
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Protocol   string
	Duration   time.Duration
}

var (
	ErrOriginViolation = errors.New("request escaped the authorized origin")
	ErrBlockedAddress  = errors.New("destination address is forbidden by runner network policy")
	ErrBodyLimit       = errors.New("HTTP body exceeded the configured hard limit")
)

// publicRunnerSpecialUsePrefixes is a fail-closed projection of the IANA IPv4
// and IPv6 special-purpose registries. Project-operated public runners do not
// dial special-use space even when an individual assignment is globally
// reachable; local authorized testing uses NetworkLocalTarget instead.
var publicRunnerSpecialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
}

// alwaysBlockedDestinations are metadata-service addresses that must never be
// contacted by any runner mode. The link-local address is listed explicitly
// even though the broader link-local rule below also rejects it: keeping the
// complete metadata denylist visible makes accidental policy regressions
// easier to review.
var alwaysBlockedDestinations = map[netip.Addr]struct{}{
	netip.MustParseAddr("169.254.169.254"): {},
	netip.MustParseAddr("100.100.100.200"): {},
	netip.MustParseAddr("fd00:ec2::254"):   {},
}

func New(policy Policy) (*Client, error) {
	origin, err := parseOrigin(policy.AllowedOrigin)
	if err != nil {
		return nil, err
	}
	if policy.Mode == "" {
		policy.Mode = NetworkLocalTarget
	}
	if policy.Mode != NetworkLocalTarget && policy.Mode != NetworkPublicRunner {
		return nil, fmt.Errorf("unknown network mode %q", policy.Mode)
	}
	if origin.Scheme == "http" && !policy.AllowPlainHTTP {
		return nil, errors.New("plain HTTP requires explicit AllowPlainHTTP")
	}
	if policy.Redirects == "" {
		policy.Redirects = RedirectNone
	}
	if policy.Redirects != RedirectNone && policy.Redirects != RedirectSameOrigin {
		return nil, errors.New("invalid redirect policy")
	}
	if policy.MaxRedirects <= 0 || policy.MaxRedirects > 10 {
		policy.MaxRedirects = 3
	}
	if policy.MaxRequestBytes <= 0 {
		policy.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if policy.MaxResponseBytes <= 0 {
		policy.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if policy.Timeout <= 0 {
		policy.Timeout = 30 * time.Second
	}
	if policy.Timeout > 10*time.Minute {
		return nil, errors.New("transport timeout exceeds the ten-minute safety ceiling")
	}
	resolver := policy.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := policy.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: min(policy.Timeout, 10*time.Second), KeepAlive: 30 * time.Second}
	}
	dialContext := originDialer(origin, policy.Mode, resolver, dialer)
	httpTransport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   min(policy.Timeout, 10*time.Second),
		ResponseHeaderTimeout: policy.Timeout,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
	}
	if policy.TLSConfig != nil {
		tlsInput := *policy.TLSConfig
		if tlsInput.ServerName == "" {
			tlsInput.ServerName = origin.Hostname()
		}
		if !strings.EqualFold(tlsInput.ServerName, origin.Hostname()) {
			return nil, errors.New("TLS server name must match the authorized origin host")
		}
		config, err := makeTLSConfig(tlsInput)
		if err != nil {
			return nil, err
		}
		httpTransport.TLSClientConfig = config
	}
	client := &http.Client{Transport: httpTransport, Timeout: policy.Timeout}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if policy.Redirects == RedirectNone {
			return http.ErrUseLastResponse
		}
		if len(via) >= policy.MaxRedirects {
			return errors.New("redirect limit exceeded")
		}
		if !sameOrigin(origin, request.URL) {
			return ErrOriginViolation
		}
		// Authentication headers are never copied by this package. Go may copy
		// caller headers on same-origin redirects, which is the approved scope.
		return nil
	}
	return &Client{origin: origin, client: client, maxRequestBytes: policy.MaxRequestBytes, maxResponseBytes: policy.MaxResponseBytes}, nil
}

// Do sends one request to a relative path within the exact authorized origin.
// Absolute paths, userinfo, fragments, and cross-origin URLs are rejected.
func (client *Client) Do(ctx context.Context, method, path string, headers http.Header, body []byte) (Response, error) {
	if client == nil || client.client == nil {
		return Response{}, errors.New("transport client is nil")
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	if method == "" || strings.ContainsAny(method, " \t\r\n") {
		return Response{}, errors.New("invalid HTTP method")
	}
	if int64(len(body)) > client.maxRequestBytes {
		return Response{}, ErrBodyLimit
	}
	reference, err := url.Parse(path)
	if err != nil || reference.IsAbs() || reference.Host != "" || reference.User != nil || reference.Fragment != "" || !strings.HasPrefix(reference.Path, "/") {
		return Response{}, errors.New("request path must be an absolute-path reference without origin or fragment")
	}
	target := client.origin.ResolveReference(reference)
	if !sameOrigin(client.origin, target) {
		return Response{}, ErrOriginViolation
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	request.Header = cloneHeaders(headers)
	request.Close = false
	started := time.Now()
	response, err := client.client.Do(request)
	duration := time.Since(started)
	if err != nil {
		return Response{}, err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, client.maxResponseBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return Response{}, err
	}
	if int64(len(payload)) > client.maxResponseBytes {
		zero(payload)
		return Response{}, ErrBodyLimit
	}
	return Response{StatusCode: response.StatusCode, Header: cloneHeaders(response.Header), Body: payload, Protocol: response.Proto, Duration: duration}, nil
}

func (client *Client) CloseIdleConnections() {
	if client != nil && client.client != nil {
		client.client.CloseIdleConnections()
	}
}

func parseOrigin(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("allowed origin must contain exactly scheme and host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("allowed origin scheme must be HTTP or HTTPS")
	}
	parsed.Path, parsed.RawPath = "", ""
	return parsed, nil
}

func sameOrigin(left, right *url.URL) bool {
	return left != nil && right != nil && strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(canonicalHost(left), canonicalHost(right))
}

func canonicalHost(value *url.URL) string {
	host := strings.ToLower(value.Hostname())
	port := value.Port()
	if port == "" {
		if value.Scheme == "https" {
			port = "443"
		} else if value.Scheme == "http" {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}

func originDialer(origin *url.URL, mode NetworkMode, resolver Resolver, dialer contextDialer) func(context.Context, string, string) (net.Conn, error) {
	authorized := canonicalHost(origin)
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(net.JoinHostPort(host, port), authorized) {
			return nil, ErrOriginViolation
		}
		addresses := []netip.Addr(nil)
		if literal, parseErr := netip.ParseAddr(host); parseErr == nil {
			// Never pass an IP literal through DNS. Besides avoiding needless
			// resolver behavior, this guarantees that a forbidden literal cannot
			// be remapped to a different address before policy evaluation.
			addresses = []netip.Addr{literal}
		} else {
			addresses, err = resolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("resolve authorized host: %w", err)
			}
		}
		if len(addresses) == 0 {
			return nil, errors.New("authorized host resolved to no addresses")
		}
		// Validate the complete answer set before trying any address. A DNS
		// response that mixes an allowed address with a forbidden one fails
		// closed and cannot make policy depend on answer order.
		for _, address := range addresses {
			if isAlwaysBlocked(address) || mode == NetworkPublicRunner && !isPublic(address) {
				return nil, ErrBlockedAddress
			}
		}
		var lastErr error
		for _, address := range addresses {
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
			if err == nil {
				return connection, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = ErrBlockedAddress
		}
		return nil, lastErr
	}
}

func isAlwaysBlocked(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() {
		return true
	}
	if address.Is6() {
		// Zones identify an interface, not a different destination. They must
		// not make a listed IPv6 metadata address compare differently.
		address = address.WithZone("")
	}
	if address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return true
	}
	_, blocked := alwaysBlockedDestinations[address]
	return blocked
}

func isPublic(address netip.Addr) bool {
	address = address.Unmap()
	if isAlwaysBlocked(address) || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() {
		return false
	}
	for _, prefix := range publicRunnerSpecialUsePrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func cloneHeaders(input http.Header) http.Header {
	if input == nil {
		return make(http.Header)
	}
	return input.Clone()
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
