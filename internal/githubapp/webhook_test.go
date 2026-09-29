// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package githubapp_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/githubapp"
)

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestValidWebhookSignature(t *testing.T) {
	const secret = "webhook-secret-canary"
	body := []byte(`{"zen":"design for failure"}`)
	key := credentials.NewSecret(secret)

	if !githubapp.ValidWebhookSignature(body, sign(secret, body), key) {
		t.Fatal("a matching sha256 signature was rejected")
	}
	if githubapp.ValidWebhookSignature(body, sign("other-secret", body), key) {
		t.Fatal("a signature from a different secret was accepted")
	}
	if githubapp.ValidWebhookSignature([]byte(`{"zen":"changed"}`), sign(secret, body), key) {
		t.Fatal("a signature over a different body was accepted")
	}
	if githubapp.ValidWebhookSignature(body, sign(secret, body), credentials.Secret{}) {
		t.Fatal("an empty secret accepted a signature")
	}
	for _, header := range []string{
		"",
		"sha1=" + hex.EncodeToString(body),
		"sha256=",
		"sha256=zzzz",
		"sha256=" + hex.EncodeToString(body), // well-formed, wrong length and value
		"SHA256=" + sign(secret, body)[len("sha256="):],
	} {
		if githubapp.ValidWebhookSignature(body, header, key) {
			t.Fatalf("malformed header accepted: %q", header)
		}
	}
	// Surrounding whitespace is not part of the MAC GitHub sends, and a
	// proxy that adds it must not turn a valid delivery into a rejection.
	if !githubapp.ValidWebhookSignature(body, "  "+sign(secret, body)+"\n", key) {
		t.Fatal("surrounding whitespace on an otherwise valid header was rejected")
	}
}
