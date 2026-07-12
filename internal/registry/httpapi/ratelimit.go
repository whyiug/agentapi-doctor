package httpapi

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type rateWindow struct {
	started time.Time
	count   int
}

type fixedWindowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]rateWindow
}

func newFixedWindowLimiter(limit int, window time.Duration) *fixedWindowLimiter {
	return &fixedWindowLimiter{limit: limit, window: window, entries: make(map[string]rateWindow)}
}

func (limiter *fixedWindowLimiter) allow(key string, now time.Time) (bool, int, time.Duration) {
	if limiter.limit <= 0 {
		return true, 0, 0
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if _, exists := limiter.entries[key]; !exists && len(limiter.entries) >= 4096 {
		// Bound attacker-controlled source cardinality.  Overflow sources share
		// one bucket rather than growing the map without limit.
		key = "overflow"
	}
	entry := limiter.entries[key]
	if entry.started.IsZero() || now.Sub(entry.started) >= limiter.window || now.Before(entry.started) {
		entry = rateWindow{started: now}
	}
	entry.count++
	limiter.entries[key] = entry
	if len(limiter.entries) > 4096 {
		for candidate, candidateEntry := range limiter.entries {
			if now.Sub(candidateEntry.started) >= limiter.window {
				delete(limiter.entries, candidate)
			}
		}
	}
	remaining := max(limiter.limit-entry.count, 0)
	retry := entry.started.Add(limiter.window).Sub(now)
	return entry.count <= limiter.limit, remaining, retry
}

func remoteRateKey(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if request.RemoteAddr == "" {
		return "unknown"
	}
	return request.RemoteAddr
}

func setRateHeaders(writer http.ResponseWriter, limit, remaining int) {
	if limit <= 0 {
		return
	}
	writer.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
	writer.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
}
