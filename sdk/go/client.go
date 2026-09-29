// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package sdk is the authenticated AppHub HTTP client. Wire models are generated
// from api/openapi.yaml; credentials never cross a server or resource boundary.
package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 -generate types -package sdk -templates templates -o models.gen.go ../../api/openapi.yaml

// Client uses the OS-user credential store and never follows HTTP redirects.
// Server is informational; changing it does not retarget an authenticated client.
type Client struct {
	Server string
	origin string
	http   *http.Client
}

func canonicalServer(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", errors.New("server must be a single HTTPS origin without credentials, path, query, or fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if u.Scheme != "https" && (u.Scheme != "http" || ip == nil || !ip.IsLoopback()) {
		return "", errors.New("server must use HTTPS (HTTP is allowed only for a literal loopback development address)")
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid server port")
		}
		port = strconv.Itoa(n)
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if ip != nil {
		host = ip.String()
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	u.Path = ""
	return u.String(), nil
}

// NewClient selects credentials only for the supplied canonical origin.
func NewClient(server string) (*Client, error) {
	origin, err := canonicalServer(server)
	if err != nil {
		return nil, err
	}
	return &Client{Server: origin, origin: origin, http: &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *Client) checkServer() error {
	if c == nil || c.origin == "" || c.Server != c.origin || c.http == nil {
		return errors.New("invalid client; construct a separate NewClient for each server")
	}
	return nil
}

// APIError contains only the backend's structured public error, never a raw
// response body, provider diagnostic, or authentication secret.
type APIError struct {
	StatusCode int
	Response   ErrorResponse
}

func (e *APIError) Error() string {
	return fmt.Sprintf("AppHub HTTP %d: %s: %s", e.StatusCode, e.Response.Error.Code, e.Response.Error.Message)
}

// UncertainError means a mutation was transmitted but its outcome could not be
// observed. Retry only with the SAME request and idempotency key, or reread it.
type UncertainError struct {
	Method, Path, IdempotencyKey string
	Cause                        error
}

func (e *UncertainError) Error() string {
	return "AppHub mutation outcome is uncertain; inspect the durable resource or retry the identical request with its original idempotency key"
}
func (e *UncertainError) Unwrap() error { return e.Cause }

func apiPath(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Fragment != "" || !strings.HasPrefix(u.Path, "/api/v1/") || strings.Contains(u.Path, "\\") || path.Clean(u.Path) != u.Path || strings.ContainsAny(u.Path, "\r\n\x00") {
		return nil, errors.New("API path must be a root-relative /api/v1/ path without traversal or fragment")
	}
	return u, nil
}

// Do performs a bounded authenticated API call. Inputs are encoded once and a
// 401 causes at most one forced refresh; no network-error retry is performed.
// Headers and the encoded request, including Idempotency-Key, survive that retry.
func (c *Client) Do(ctx context.Context, method, requestPath string, input, output any, headers http.Header) error {
	if err := c.checkServer(); err != nil {
		return err
	}
	u, err := apiPath(requestPath)
	if err != nil {
		return err
	}
	var body []byte
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode API input: %w", err)
		}
		if len(body) > 128<<10 {
			return errors.New("API input exceeds 128 KiB")
		}
	}
	token, err := c.accessToken(ctx, "")
	if err != nil {
		return err
	}
	for attempt := range 2 {
		req, err := http.NewRequestWithContext(ctx, method, c.origin+u.String(), bytes.NewReader(body))
		if err != nil {
			return err
		}
		if headers != nil {
			req.Header = headers.Clone()
		}
		req.Header.Del("Cookie")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		if input != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		response, err := c.http.Do(req)
		if err != nil {
			return mutationError(method, requestPath, headers, err)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
		// The read determines response validity; closing cannot undo a completed mutation.
		_ = response.Body.Close()
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 {
			token, err = c.accessToken(ctx, token)
			if err != nil {
				return err
			}
			continue
		}
		if response.StatusCode == http.StatusUnauthorized {
			return errors.Join(ErrReauthenticationRequired, c.invalidateToken(ctx, token))
		}
		if readErr != nil || len(payload) > 4<<20 {
			return mutationError(method, requestPath, headers, errors.New("could not read bounded API response"))
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			var envelope ErrorResponse
			if json.Unmarshal(payload, &envelope) != nil || envelope.Error.Code == "" {
				return fmt.Errorf("AppHub request failed (HTTP %d); no structured error returned", response.StatusCode)
			}
			return &APIError{StatusCode: response.StatusCode, Response: envelope}
		}
		if output == nil || response.StatusCode == http.StatusNoContent {
			return nil
		}
		if err := json.Unmarshal(payload, output); err != nil {
			return mutationError(method, requestPath, headers, errors.New("invalid API response"))
		}
		return nil
	}
	return ErrReauthenticationRequired
}

func mutationError(method, requestPath string, headers http.Header, err error) error {
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		return fmt.Errorf("AppHub request failed: %w", err)
	}
	return &UncertainError{Method: method, Path: requestPath, IdempotencyKey: headers.Get("Idempotency-Key"), Cause: err}
}
