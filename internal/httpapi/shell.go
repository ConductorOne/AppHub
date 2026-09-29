// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package httpapi hosts AppHub's same-origin HTTP transports and frontend.
package httpapi

import (
	"context"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/conductorone/apphub/internal/controlplane"
)

const maxRequestBodyBytes = 128 << 10

// NewMux creates the public health endpoints and confined frontend handler.
// Additional API and authentication routes may be registered on the returned
// mux. A nil dependency check deliberately leaves readiness unavailable.
func NewMux(staticDir string, ready func(context.Context) error) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeHealth(w, r, http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready == nil || ready(r.Context()) != nil {
			writeHealth(w, r, http.StatusServiceUnavailable)
			return
		}
		writeHealth(w, r, http.StatusOK)
	})
	mux.Handle("/", staticHandler{directory: staticDir})
	return mux
}

// NewServer applies the transport deadlines and request bounds shared by all
// routes. Handlers decoding streamed bodies must handle *http.MaxBytesError as
// 413; requests declaring an oversized Content-Length are rejected up front.
func NewServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: address,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if r.ContentLength > maxRequestBodyBytes {
				if strings.HasPrefix(r.URL.Path, "/api/") {
					id := controlplane.NewID()
					w.Header().Set("X-Request-ID", id)
					writeAPIJSON(w, http.StatusRequestEntityTooLarge, controlplane.ErrorResponse{
						Error:     controlplane.Problem(413, "request_too_large", "Request body exceeds 128 KiB."),
						RequestID: id,
					})
				} else {
					http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				}
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}

func writeHealth(w http.ResponseWriter, r *http.Request, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		if status == http.StatusOK {
			_, _ = w.Write([]byte("ok\n"))
		} else {
			_, _ = w.Write([]byte("unavailable\n"))
		}
	}
}

type staticHandler struct {
	directory string
}

func (h staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The same SPA entrypoint serves login and OAuth consent. SameSite=Lax
	// cookies do not prevent a sibling subdomain from framing this document.
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	if reservedPath(r.URL.Path) || h.directory == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if name == "" {
		if !htmlNavigation(r) {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
	}
	if !safeAssetPath(name) {
		http.NotFound(w, r)
		return
	}

	// OpenInRoot confines resolution, including symlinks, at the filesystem
	// operation itself rather than relying on a raceable lexical prefix check.
	file, err := os.OpenInRoot(h.directory, name)
	if errors.Is(err, fs.ErrNotExist) && spaPath(name) && htmlNavigation(r) {
		name = "index.html"
		file, err = os.OpenInRoot(h.directory, name)
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = file.Close() }() // Read-only cleanup cannot change an already served response.
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}

	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	// Revalidate the entrypoint so a rollout cannot strand clients on an old
	// asset manifest. Other assets retain standard conditional/range serving.
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

func reservedPath(name string) bool {
	for _, prefix := range [...]string{"/api", "/auth", "/oauth", "/mcp", "/.well-known", "/healthz", "/readyz"} {
		if name == prefix || strings.HasPrefix(name, prefix+"/") {
			return true
		}
	}
	return false
}

func safeAssetPath(name string) bool {
	if !fs.ValidPath(name) || strings.ContainsAny(name, "\\\x00") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") || strings.ContainsFunc(part, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return false
		}
	}
	return true
}

func spaPath(name string) bool {
	// A missing asset is never replaced with HTML, even when a browser sends
	// Accept: text/html. Vite's asset directory also contains extensionless files.
	return path.Ext(name) == "" && name != "assets" && !strings.HasPrefix(name, "assets/")
}

func htmlNavigation(r *http.Request) bool {
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		return false
	}
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" && dest != "document" && dest != "iframe" {
		return false
	}
	for _, accept := range strings.Split(r.Header.Get("Accept"), ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(accept))
		if err != nil || mediaType != "text/html" {
			continue
		}
		if value, ok := params["q"]; ok {
			quality, err := strconv.ParseFloat(value, 64)
			if err != nil || !(quality > 0 && quality <= 1) {
				continue
			}
		}
		return true
	}
	return false
}
