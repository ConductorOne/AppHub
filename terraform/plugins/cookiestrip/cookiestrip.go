// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package cookiestrip is a Traefik local middleware. It removes oauth2-proxy's
// shared-domain cookies after ForwardAuth has checked them and before an app is
// called. A malformed Cookie header is rejected, never passed through.
package cookiestrip

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// Config is Traefik's plugin configuration. Enabled is deliberately required
// so a missing or misspelled ECS label fails closed at middleware creation.
// The cookie name is fixed in oauth2_proxy.tf and must change here with it.
type Config struct {
	Enabled bool `json:"enabled"`
}

func CreateConfig() *Config { return &Config{} }

func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	if config == nil || !config.Enabled {
		return nil, errors.New("cookie strip middleware must be enabled")
	}
	return &middleware{next: next}, nil
}

type middleware struct{ next http.Handler }

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cookies := r.Header.Values("Cookie")
	if len(cookies) == 0 {
		m.next.ServeHTTP(w, r)
		return
	}

	filtered := make([]string, 0, len(cookies))
	for _, header := range cookies {
		value, err := filter(header)
		if err != nil {
			http.Error(w, "invalid Cookie header", http.StatusBadRequest)
			return
		}
		if value != "" {
			filtered = append(filtered, value)
		}
	}

	// Never forward a raw Cookie header, including duplicate headers. Mutate
	// only after every field was validated so no partial request can escape.
	r.Header.Del("Cookie")
	for _, header := range filtered {
		r.Header.Add("Cookie", header)
	}
	m.next.ServeHTTP(w, r)
}

var errInvalidCookie = errors.New("invalid Cookie header")

func filter(header string) (string, error) {
	if header == "" {
		return "", errInvalidCookie
	}
	var kept strings.Builder
	for {
		field, rest, more := strings.Cut(header, ";")
		field = strings.Trim(field, " \t")
		name, value, ok := strings.Cut(field, "=")
		if !ok {
			return "", errInvalidCookie
		}
		name = strings.Trim(name, " \t")
		value = strings.Trim(value, " \t")
		if !validName(name) || !validValue(value) {
			return "", errInvalidCookie
		}
		// oauth2-proxy also writes numbered split-session cookies and CSRF
		// cookies. Reserve its full underscore namespace, regardless of case.
		const session = "_oauth2_proxy"
		if !(strings.EqualFold(name, session) ||
			len(name) > len(session) && name[len(session)] == '_' && strings.EqualFold(name[:len(session)], session)) {
			if kept.Len() > 0 {
				kept.WriteString("; ")
			}
			kept.WriteString(name)
			kept.WriteByte('=')
			kept.WriteString(value)
		}
		if !more {
			break
		}
		header = rest
	}
	return kept.String(), nil
}

func validName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return true
}

func validValue(value string) bool {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '!' && (c < '#' || c > '+') && (c < '-' || c > ':') && (c < '<' || c > '[') && (c < ']' || c > '~') {
			return false
		}
	}
	return true
}
