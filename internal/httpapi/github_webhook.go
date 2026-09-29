// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/githubapp"
)

// maxWebhookBodyBytes bounds a GitHub delivery. The HMAC is over the raw
// bytes, so the body is read once and never re-encoded. One mebibyte covers
// the ping and installation payloads this receiver acknowledges; a larger
// delivery is rejected rather than buffered without a limit.
const maxWebhookBodyBytes = 1 << 20

// RegisterGitHubWebhook installs the unauthenticated GitHub App webhook
// receiver. Authentication is the HMAC in X-Hub-Signature-256, not a
// browser session or an API token. A zero secret fails closed: every
// delivery is rejected, and the handler never accepts an unsigned body.
//
// A matching signature is acknowledged with 204. The payload is not
// applied; installation records are still refreshed by the worker.
func RegisterGitHubWebhook(mux *http.ServeMux, secret credentials.Secret) {
	mux.HandleFunc("POST "+githubapp.WebhookPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if secret.IsZero() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		signatures := r.Header.Values("X-Hub-Signature-256")
		if len(signatures) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !githubapp.ValidWebhookSignature(body, signatures[0], secret) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
