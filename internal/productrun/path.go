package productrun

import (
	"errors"
	"fmt"
	"net/url"
	pathpkg "path"
	"strings"

	"github.com/whyiug/agentapi-doctor/internal/config"
)

type targetRoute struct {
	origin       string
	endpointPath string
}

// routeTarget deliberately separates the transport authority from the base
// path. transport.Client receives only scheme+host; rawdriver receives one
// canonical origin-free path. This prevents a configured /v1 prefix from
// being dropped or duplicated by URL reference resolution.
func routeTarget(target config.Target) (targetRoute, error) {
	if err := target.Validate(); err != nil {
		return targetRoute{}, err
	}
	parsed, err := url.Parse(target.BaseURL)
	if err != nil {
		return targetRoute{}, err
	}
	basePath, err := canonicalBasePath(parsed)
	if err != nil {
		return targetRoute{}, err
	}
	suffix := ""
	switch target.Protocol {
	case "openai-chat":
		suffix = "chat/completions"
	case "openai-responses":
		suffix = "responses"
	case "anthropic-messages":
		suffix = "messages"
	default:
		return targetRoute{}, fmt.Errorf("unsupported target protocol %q", target.Protocol)
	}
	// A non-root base path is a complete API prefix. This matches common
	// OpenAI-compatible deployments whose version prefix is not /v1 (for
	// example /api/v3) and avoids silently inserting a path segment into a
	// gateway route. An origin-only URL retains the convenient /v1 default.
	prefix := basePath
	if prefix == "/" {
		prefix = "/v1"
	}
	endpoint := pathpkg.Join(prefix, suffix)
	if !strings.HasPrefix(endpoint, "/") || pathpkg.Clean(endpoint) != endpoint || strings.Contains(endpoint, "\\") {
		return targetRoute{}, errors.New("derived endpoint path is not canonical")
	}
	origin := (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String()
	return targetRoute{origin: origin, endpointPath: endpoint}, nil
}

func canonicalBasePath(parsed *url.URL) (string, error) {
	if parsed == nil {
		return "", errors.New("base URL is required")
	}
	// Escaped separators and dot segments create different interpretations in
	// proxies and URL libraries. The candidate runner rejects them rather than
	// choosing one interpretation silently.
	if parsed.RawPath != "" || strings.Contains(parsed.EscapedPath(), "%") || strings.Contains(parsed.Path, "\\") {
		return "", errors.New("base URL path cannot contain escapes or backslashes")
	}
	value := parsed.Path
	if value == "" || value == "/" {
		return "/", nil
	}
	withoutTrailing := strings.TrimSuffix(value, "/")
	if withoutTrailing == "" || !strings.HasPrefix(withoutTrailing, "/") || pathpkg.Clean(withoutTrailing) != withoutTrailing || strings.Contains(withoutTrailing, "//") {
		return "", errors.New("base URL path must be canonical and may only have one trailing slash")
	}
	return withoutTrailing, nil
}
