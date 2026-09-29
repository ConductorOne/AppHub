// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/githubapp"
)

func webhookSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func postWebhook(secret credentials.Secret, body, signature, contentType string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	RegisterGitHubWebhook(mux, secret)
	request := httptest.NewRequest(http.MethodPost, githubapp.WebhookPath, strings.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if signature != "" {
		request.Header.Set("X-Hub-Signature-256", signature)
	}
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	return response
}

func TestGitHubWebhookRequiresAMatchingSignature(t *testing.T) {
	const secret = "webhook-secret-canary"
	body := `{"zen":"design for failure"}`
	key := credentials.NewSecret(secret)

	ok := postWebhook(key, body, webhookSignature(secret, []byte(body)), "application/json")
	if ok.Code != http.StatusNoContent || ok.Body.Len() != 0 {
		t.Fatalf("valid delivery: status %d body %q", ok.Code, ok.Body.String())
	}

	cases := []struct {
		name        string
		secret      credentials.Secret
		body        string
		signature   string
		contentType string
		want        int
	}{
		{name: "wrong secret", secret: key, body: body, signature: webhookSignature("other", []byte(body)), contentType: "application/json", want: http.StatusUnauthorized},
		{name: "tampered body", secret: key, body: body + " ", signature: webhookSignature(secret, []byte(body)), contentType: "application/json", want: http.StatusUnauthorized},
		{name: "missing signature", secret: key, body: body, contentType: "application/json", want: http.StatusUnauthorized},
		{name: "sha1 header", secret: key, body: body, signature: "sha1=abcd", contentType: "application/json", want: http.StatusUnauthorized},
		{name: "unconfigured", secret: credentials.Secret{}, body: body, signature: webhookSignature(secret, []byte(body)), contentType: "application/json", want: http.StatusUnauthorized},
		{name: "form body", secret: key, body: body, signature: webhookSignature(secret, []byte(body)), contentType: "application/x-www-form-urlencoded", want: http.StatusUnsupportedMediaType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := postWebhook(tc.secret, tc.body, tc.signature, tc.contentType)
			if response.Code != tc.want || response.Body.Len() != 0 {
				t.Fatalf("status %d body %q, want %d and an empty body", response.Code, response.Body.String(), tc.want)
			}
		})
	}
}

func TestGitHubWebhookRejectsASecondSignatureHeader(t *testing.T) {
	const secret = "webhook-secret-canary"
	body := `{"zen":"design for failure"}`
	mux := http.NewServeMux()
	RegisterGitHubWebhook(mux, credentials.NewSecret(secret))
	request := httptest.NewRequest(http.MethodPost, githubapp.WebhookPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Add("X-Hub-Signature-256", webhookSignature(secret, []byte(body)))
	request.Header.Add("X-Hub-Signature-256", webhookSignature("other", []byte(body)))
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", response.Code)
	}
}

func TestGitHubWebhookRejectsAnOversizedBody(t *testing.T) {
	const secret = "webhook-secret-canary"
	body := strings.Repeat("a", maxWebhookBodyBytes+1)
	response := postWebhook(credentials.NewSecret(secret), body, webhookSignature(secret, []byte(body)), "application/json; charset=utf-8")
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", response.Code)
	}
}
