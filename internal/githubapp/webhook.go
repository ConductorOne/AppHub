// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package githubapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/conductorone/apphub/credentials"
)

// WebhookPath is where GitHub posts App webhook deliveries. The route is
// unauthenticated: the HMAC in X-Hub-Signature-256 is the credential.
const WebhookPath = "/api/v1/github/webhook"

// ValidWebhookSignature reports whether header is GitHub's
// X-Hub-Signature-256 over the raw body using secret.
//
// A zero secret, a missing or malformed header, and a MAC that does not
// match are all false. The comparison is constant time. The older sha1
// X-Hub-Signature header is not accepted.
func ValidWebhookSignature(body []byte, header string, secret credentials.Secret) bool {
	if secret.IsZero() {
		return false
	}
	hexPart, ok := strings.CutPrefix(strings.TrimSpace(header), "sha256=")
	if !ok || hexPart == "" {
		return false
	}
	got, err := hex.DecodeString(hexPart)
	if err != nil || len(got) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, []byte(credentials.Reveal(secret)))
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}
