// Package matrix serves the dependency-free public Registry matrix UI.
package matrix

import (
	"embed"
	"net/http"
	"path"
	"strings"
)

//go:embed index.html app.js style.css
var assets embed.FS

type handler struct{}

func Handler() http.Handler { return handler{} }

func (handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if request.URL.RawQuery != "" {
		http.Error(writer, "query parameters are not accepted for static assets", http.StatusBadRequest)
		return
	}
	name := ""
	switch request.URL.Path {
	case "/", "/matrix", "/matrix/":
		name = "index.html"
	case "/matrix/app.js":
		name = "app.js"
	case "/matrix/style.css":
		name = "style.css"
	default:
		http.NotFound(writer, request)
		return
	}
	if path.Base(name) != name || strings.Contains(name, "\\") {
		http.NotFound(writer, request)
		return
	}
	raw, err := assets.ReadFile(name)
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Frame-Options", "DENY")
	writer.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	if name == "index.html" {
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-cache")
	} else if name == "app.js" {
		writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		writer.Header().Set("Cache-Control", "public, max-age=300")
	} else {
		writer.Header().Set("Content-Type", "text/css; charset=utf-8")
		writer.Header().Set("Cache-Control", "public, max-age=300")
	}
	writer.Header().Set("Content-Length", fmtInt(len(raw)))
	writer.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(raw)
	}
}

func fmtInt(value int) string {
	if value == 0 {
		return "0"
	}
	buffer := [20]byte{}
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[position:])
}
