// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

type clientMetadata struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}
type metadataCacheEntry struct {
	metadata *clientMetadata
	expires  time.Time
	access   time.Time
}

var errClient = errors.New("invalid public OAuth client")

// safeRedirectURL applies the hygiene checks shared by every accepted redirect
// scheme: bounded length, no userinfo/fragment/opaque, no raw control/escape
// bytes, and no query keys the authorization response itself uses.
func safeRedirectURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(raw, "\\\r\n\t") {
		return nil, false
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, false
	}
	for _, k := range []string{"code", "error", "state", "iss"} {
		if _, exists := q[k]; exists {
			return nil, false
		}
	}
	return u, true
}
func httpsRedirect(raw string) bool {
	u, ok := safeRedirectURL(raw)
	return ok && u.Scheme == "https"
}

// loopbackHosts are the RFC 8252 §7.3/§8.3 loopback interface names a native
// app may bind its ephemeral redirect listener to.
var loopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

// loopbackRedirect reports whether raw is an http redirect to a loopback host
// with the same hygiene as httpsRedirect. The port, if any, is not checked
// here: a CIMD-registered loopback redirect may omit it entirely.
func loopbackRedirect(raw string) bool {
	u, ok := safeRedirectURL(raw)
	return ok && u.Scheme == "http" && loopbackHosts[u.Hostname()]
}

// loopbackRedirectMatches reports whether requested is the exact registered
// redirect, or, when registered is itself a loopback redirect, whether they
// agree on hostname/path/query while requested supplies its own explicit
// numeric ephemeral port (or none). This lets a CIMD register
// "http://localhost/callback" and satisfy an authorize call naming whatever
// port the native client's loopback listener actually bound.
func loopbackRedirectMatches(registered, requested string) bool {
	if registered == requested {
		return true
	}
	ru, ok := safeRedirectURL(registered)
	if !ok || ru.Scheme != "http" || !loopbackHosts[ru.Hostname()] {
		return false
	}
	qu, ok := safeRedirectURL(requested)
	if !ok || qu.Scheme != "http" || !loopbackHosts[qu.Hostname()] {
		return false
	}
	if port := qu.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n <= 0 || n > 65535 {
			return false
		}
	}
	return ru.Hostname() == qu.Hostname() && ru.EscapedPath() == qu.EscapedPath() && ru.RawQuery == qu.RawQuery
}
func nativeRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	return err == nil && port > 0 && port <= 65535 && u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.Host == net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) && u.Path == "/callback" && u.RawPath == "" && u.User == nil && u.Fragment == "" && u.RawQuery == "" && !u.ForceQuery && u.Opaque == ""
}
func metadataURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(raw) <= 2048 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.Opaque == "" && u.EscapedPath() != "" && u.EscapedPath() != "/" && !strings.ContainsAny(raw, "\\\r\n\t")
}
func (s *Server) validateClient(ctx context.Context, id, redirect string) error {
	if id == "apphub-cli" {
		if nativeRedirect(redirect) {
			return nil
		}
		return errClient
	}
	if redirects, ok := s.clients[id]; ok {
		if slices.Contains(redirects, redirect) {
			return nil
		}
		return errClient
	}
	metadata, err := s.resolveMetadata(ctx, id)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(metadata.RedirectURIs, func(registered string) bool {
		return loopbackRedirectMatches(registered, redirect)
	}) {
		return errClient
	}
	return nil
}
func (s *Server) resolveMetadata(ctx context.Context, id string) (*clientMetadata, error) {
	if !metadataURL(id) {
		return nil, errClient
	}
	now := time.Now()
	s.cacheMu.Lock()
	if entry, ok := s.cache[id]; ok && now.Before(entry.expires) {
		entry.access = now
		s.cache[id] = entry
		s.cacheMu.Unlock()
		if entry.metadata == nil {
			return nil, errClient
		}
		return entry.metadata, nil
	}
	delete(s.cache, id)
	s.cacheMu.Unlock()
	// Bound in-flight DNS/TLS work as well as response bytes and cached entries.
	select {
	case s.fetchSlots <- struct{}{}:
		defer func() { <-s.fetchSlots }()
	default:
		return nil, errClient
	}
	metadata, err := fetchMetadata(ctx, s.metadataClient, id)
	ttl := time.Hour
	if err != nil {
		ttl = 30 * time.Second
	}
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if len(s.cache) >= 128 {
		var oldest string
		var at time.Time
		for key, entry := range s.cache {
			if oldest == "" || entry.access.Before(at) {
				oldest = key
				at = entry.access
			}
		}
		delete(s.cache, oldest)
	}
	s.cache[id] = metadataCacheEntry{metadata: metadata, expires: now.Add(ttl), access: now}
	return metadata, err
}
func newMetadataHTTPClient() *http.Client {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errClient
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errClient
		}
		// Reject a mixed public/private answer, not merely the first unsafe address.
		// Dial numeric addresses only: DNS cannot change the destination after check.
		for _, ip := range ips {
			if !publicIP(ip) {
				return nil, errClient
			}
		}
		dialer := net.Dialer{Timeout: 5 * time.Second}
		for _, ip := range ips {
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, errClient
	}
	return &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errClient }}
}

var deniedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
		return false
	}
	// Only native global IPv6 unicast; this also excludes NAT64/translation
	// prefixes that could encode a private IPv4 destination.
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range deniedNetworks {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
func fetchMetadata(ctx context.Context, client *http.Client, id string) (*clientMetadata, error) {
	if !metadataURL(id) {
		return nil, errClient
	}
	// #nosec G704 -- metadataURL requires HTTPS; the production client from
	// newMetadataHTTPClient rejects all nonpublic DNS answers and dials checked IPs.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return nil, errClient
	}
	req.Header.Set("Accept", "application/json")
	// #nosec G704 -- The production transport pins public IPs, disables proxies
	// and redirects, and bounds DNS/dial/TLS/response time; body size is capped below.
	response, err := client.Do(req)
	if err != nil {
		return nil, errClient
	}
	defer func() { _ = response.Body.Close() }() // Cleanup cannot change metadata validation.
	if response.StatusCode != http.StatusOK {
		return nil, errClient
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	if err != nil || len(body) > 16<<10 {
		return nil, errClient
	}
	var metadata clientMetadata
	if json.Unmarshal(body, &metadata) != nil || metadata.ClientID != id || strings.TrimSpace(metadata.ClientName) == "" || metadata.TokenEndpointAuthMethod != "none" || len(metadata.RedirectURIs) == 0 || len(metadata.RedirectURIs) > 32 {
		return nil, errClient
	}
	for _, redirect := range metadata.RedirectURIs {
		if !httpsRedirect(redirect) && !loopbackRedirect(redirect) {
			return nil, errClient
		}
	}
	return &metadata, nil
}
