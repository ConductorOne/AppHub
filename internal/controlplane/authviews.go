// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import "time"

// IdentityView identifies the external account that established authentication.
type IdentityView struct {
	ProviderID string `json:"providerId"`
	Issuer     string `json:"issuer"`
	Subject    string `json:"subject"`
	Email      string `json:"email"`
}

// UserView exposes current identity and permissions; CSRFToken is browser-only.
type UserView struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Avatar string `json:"avatar"`
	Role   string `json:"role"`
	// VulnAdmin grants cross-application vulnerability finding visibility,
	// independent of Role -- see Principal.VulnAdmin.
	VulnAdmin bool `json:"vulnAdmin"`
	// EnabledFeatures lists the feature-flag keys currently enabled for this
	// identity (see FeatureFlagRecord). A feature absent from this list is
	// not merely unavailable in the UI -- nothing behind it should be
	// reachable, including by URL.
	EnabledFeatures  []string     `json:"enabledFeatures"`
	PermittedActions []string     `json:"permittedActions"`
	CSRFToken        string       `json:"csrfToken,omitempty"`
	Identity         IdentityView `json:"identity"`
}

// SessionView describes a browser session or delegated family without its credentials.
type SessionView struct {
	ID        string       `json:"id"`
	Kind      string       `json:"kind"`
	ClientID  string       `json:"clientId,omitempty"`
	Resource  string       `json:"resource,omitempty"`
	Scopes    []string     `json:"scopes,omitempty"`
	Identity  IdentityView `json:"identity"`
	Current   bool         `json:"current"`
	Revoked   bool         `json:"revoked"`
	CreatedAt time.Time    `json:"createdAt"`
	ExpiresAt time.Time    `json:"expiresAt"`
}

// ConsentView binds approval to a client, redirect, resource, scopes and external identity.
type ConsentView struct {
	TransactionID string       `json:"transactionId"`
	ClientID      string       `json:"clientId"`
	RedirectURI   string       `json:"redirectUri"`
	Resource      string       `json:"resource"`
	Scopes        []string     `json:"scopes"`
	Identity      IdentityView `json:"identity"`
	ExpiresAt     time.Time    `json:"expiresAt"`
}
