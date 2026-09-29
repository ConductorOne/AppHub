// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package serverconfig_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/serverconfig"
)

const validConfig = `publicOrigin: https://portal.example.com
listenAddress: 127.0.0.1:8080
staticDir: dist
auth:
  transactionKeyFile: ./transaction.key
  providers:
    - id: google
      label: Google
      kind: google
      clientId: apphub
      clientSecretFile: ./client.secret
      allowedDomains: [Example.COM]
      allowedEmails: [Person@Outside.Example]
  admins:
    - providerId: google
      subject: exact-subject
  clients:
    - id: remote-client
      redirectUris: [https://client.example.com/callback]
store:
  region: us-west-2
  tableName: apphub-test
targets:
  production:
    label: Production
    awsConfigFile: unavailable-aws.yaml
    deployConfig:
      resourcePrefix: apphub
      allowedSourceHosts: [github.com]
      placement:
        name: primary
      workloadIdentityMode: native
    policy:
      resourceSizes:
        - cpu: 1000
          memory: 2048
      maxReplicas: 3
      executionModes: [service, scheduled]
      publicExposure: false
source:
  repositories:
    - url: https://github.com/example/application
      auth: githubApp
      githubApp:
        appId: 123
        installationId: 456
        privateKeyFile: ./unavailable-source.pem
worker:
  workDir: /var/lib/apphub/builds
`

func configFile(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{
		"config.yaml":     contents,
		"transaction.key": strings.Repeat("K", 32),
		"client.secret":   "client-secret-canary\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "config.yaml")
}

func TestStrictYAMLRejectsUnknownNestedFieldsAndDocuments(t *testing.T) {
	for name, contents := range map[string]string{
		"top level":        validConfig + "anonymous: true\n",
		"nested provider":  strings.Replace(validConfig, "      kind: google", "      kind: google\n      clientSecret: secret-canary", 1),
		"nested policy":    strings.Replace(validConfig, "      maxReplicas: 3", "      maxReplicas: 3\n      allowAnything: true", 1),
		"nested placement": strings.Replace(validConfig, "        name: primary", "        name: primary\n        region: somewhere", 1),
		"nested worker":    validConfig + "  unexpected: true\n",
		"duplicate key":    validConfig + "publicOrigin: https://other.example.com\n",
		"second document":  validConfig + "---\npublicOrigin: https://other.example.com\n",
		"malformed secret": validConfig + "secret-canary: [\n",
		// githubAppAdmin was removed: the key store location is now always
		// derived (cmd/apphub.githubAppKeyLocation), never operator-configured.
		"removed githubAppAdmin": validConfig + "githubAppAdmin:\n  local:\n    path: ./key.json\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := serverconfig.Load(configFile(t, contents), serverconfig.ModeServe)
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("parse error exposed input")
			}
		})
	}
}

func TestServeReadsOnlyAuthenticationSecrets(t *testing.T) {
	filename := configFile(t, validConfig)
	c, err := serverconfig.Load(filename, serverconfig.ModeServe)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Reveal(c.Auth.TransactionKey) != strings.Repeat("K", 32) || credentials.Reveal(c.Auth.Providers[0].ClientSecret) != "client-secret-canary" {
		t.Fatal("authentication secrets were not loaded")
	}
	if !c.Source.Repositories[0].GitHubApp.PrivateKey.IsZero() {
		t.Fatal("serve loaded source private key")
	}
	if got, ok := c.CallbackURL("google"); !ok || got != "https://portal.example.com/auth/google/callback" {
		t.Fatalf("incorrect callback: %q, %v", got, ok)
	}
	if _, ok := c.CallbackURL("missing"); ok {
		t.Fatal("unknown provider gained callback")
	}
	if c.StaticDir != filepath.Join(filepath.Dir(filename), "dist") {
		t.Fatal("relative static directory was not config-relative")
	}
	assertNoSecrets(t, c, "client-secret-canary", strings.Repeat("K", 32))
}

func TestWorkerReadsOnlySourceSecretsAndRetainsAdmission(t *testing.T) {
	contents := strings.ReplaceAll(validConfig, "transaction.key", "missing-transaction.key")
	contents = strings.ReplaceAll(contents, "client.secret", "missing-client.secret")
	contents = strings.ReplaceAll(contents, "unavailable-source.pem", "source.pem")
	contents = strings.ReplaceAll(contents, "listenAddress: 127.0.0.1:8080\nstaticDir: dist\n", "")
	filename := configFile(t, contents)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err := os.WriteFile(filepath.Join(filepath.Dir(filename), "source.pem"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := serverconfig.Load(filename, serverconfig.ModeWorker)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Auth.TransactionKey.IsZero() || !c.Auth.Providers[0].ClientSecret.IsZero() {
		t.Fatal("worker loaded upstream authentication secrets")
	}
	if credentials.Reveal(c.Source.Repositories[0].GitHubApp.PrivateKey) != string(encoded) {
		t.Fatal("source key was not loaded")
	}
	if !c.Auth.Providers[0].Admits("member@example.com", true) || c.Auth.Admins[0].Subject != "exact-subject" {
		t.Fatal("worker lost admission policy")
	}
	if c.Worker.DeploymentTimeout != 30*time.Minute || c.Worker.HeartbeatInterval >= c.Worker.StaleAfter {
		t.Fatal("worker timing is unusable")
	}
	assertNoSecrets(t, c, "BEGIN RSA PRIVATE KEY", string(encoded))
}

func assertNoSecrets(t *testing.T, c serverconfig.Config, secrets ...string) {
	t.Helper()
	j, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	y, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{string(j), string(y), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
		for _, secret := range secrets {
			if strings.Contains(rendered, secret) {
				t.Fatal("configuration diagnostics exposed a loaded secret")
			}
		}
	}
}

func TestOriginAndAdmissionBoundaries(t *testing.T) {
	for _, origin := range []string{
		"http://portal.example.com", "https://user:pass@portal.example.com", "https://portal.example.com/",
		"https://portal.example.com/path", "https://portal.example.com?", "https://portal.example.com#",
		"//portal.example.com", "https://portal.example.com:70000", "https://portal.example.com:",
		"http://localhost:5173", "http://192.168.1.5:5173", "https://portal.example.com\\evil",
	} {
		t.Run(origin, func(t *testing.T) {
			contents := strings.Replace(validConfig, "https://portal.example.com", origin, 1)
			contents = strings.Replace(contents, "auth:\n", "auth:\n  allowLoopbackHTTP: true\n", 1)
			if _, err := serverconfig.Load(configFile(t, contents), serverconfig.ModeServe); err == nil {
				t.Fatal("invalid origin accepted")
			}
		})
	}
	for _, origin := range []string{"http://127.0.0.1:5173", "http://[::1]:5173"} {
		contents := strings.Replace(validConfig, "https://portal.example.com", origin, 1)
		if _, err := serverconfig.Load(configFile(t, contents), serverconfig.ModeServe); err == nil {
			t.Fatal("loopback HTTP accepted without explicit opt-in")
		}
		contents = strings.Replace(contents, "auth:\n", "auth:\n  allowLoopbackHTTP: true\n", 1)
		if _, err := serverconfig.Load(configFile(t, contents), serverconfig.ModeServe); err != nil {
			t.Fatal(err)
		}
	}
	c, err := serverconfig.Load(configFile(t, validConfig), serverconfig.ModeServe)
	if err != nil {
		t.Fatal(err)
	}
	p := c.Auth.Providers[0]
	for _, email := range []string{"person@outside.example", "MEMBER@EXAMPLE.COM"} {
		if !p.Admits(email, true) {
			t.Fatal("exact normalized admission rejected")
		}
		if p.Admits(email, false) {
			t.Fatal("unverified email admitted")
		}
	}
	// Derive boundary lookalikes from the reserved documentation domain.
	for _, email := range []string{"person@sub.example.com", "person@evil" + "example.com", "other@outside.example", "person@example.com" + ".evil", "Name <person@example.com>"} {
		if p.Admits(email, true) {
			t.Fatal("nonmatching email admitted")
		}
	}
}

func TestPublicOriginRequiresBrowserCanonicalSpelling(t *testing.T) {
	for _, tc := range []struct {
		origin   string
		accepted bool
	}{
		{"https://portal.example.com", true},
		{"https://portal.example.com:8443", true},
		{"https://127.0.0.1", true},
		{"http://127.0.0.1", true},
		{"http://127.0.0.1:5173", true},
		{"https://[2001:db8::1]", true},
		{"http://[::1]:5173", true},
		{"https://[::ffff:c000:201]", true},
		{"https://Example.COM:443", false},
		{"https://Portal.Example.com", false},
		{"HTTPS://portal.example.com", false},
		{"https://portal.example.com:443", false},
		{"http://127.0.0.1:80", false},
		{"https://portal.example.com:", false},
		{"https://portal.example.com:08443", false},
		{"http://127.0.0.1:05173", false},
		{"https://127.1", false},
		{"https://2130706433", false},
		{"https://0177.0.0.1", false},
		{"https://0x7f000001", false},
		{"https://127.0.0.0x1", false},
		{"https://[2001:0DB8:0:0:0:0:0:1]", false},
		{"https://[::ffff:192.0.2.1]", false},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			contents := strings.Replace(validConfig, "https://portal.example.com", tc.origin, 1)
			contents = strings.Replace(contents, "auth:\n", "auth:\n  allowLoopbackHTTP: true\n", 1)
			c, err := serverconfig.Load(configFile(t, contents), serverconfig.ModeServe)
			if !tc.accepted {
				if err == nil {
					t.Fatal("noncanonical browser origin accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("canonical browser origin rejected: %v", err)
			}
			callback, ok := c.CallbackURL("google")
			if !ok || callback != tc.origin+"/auth/google/callback" {
				t.Fatal("callback no longer shares the configured browser origin")
			}
		})
	}
	// Upstream issuers are identifiers, not browser Origin values. Applying the
	// public-origin spelling restriction here would break exact OIDC matching.
	issuer := "https://Issuer.Example.com:443/tenant"
	contents := strings.Replace(validConfig, "      kind: google", "      kind: oidc\n      issuer: "+issuer, 1)
	c, err := serverconfig.Load(configFile(t, contents), serverconfig.ModeServe)
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth.Providers[0].Issuer != issuer {
		t.Fatal("upstream issuer identity was rewritten")
	}
}

func TestInvalidOperatorPoliciesFailClosed(t *testing.T) {
	for name, change := range map[string][2]string{
		"no admission":             {"      allowedDomains: [Example.COM]\n      allowedEmails: [Person@Outside.Example]", "      allowedDomains: []"},
		"wildcard domain":          {"[Example.COM]", "['*.example.com']"},
		"unknown admin provider":   {"providerId: google", "providerId: unknown"},
		"empty admin subject":      {"subject: exact-subject", "subject: ''"},
		"missing client secret":    {"clientSecretFile: ./client.secret", "clientSecretFile: ''"},
		"wrong Google issuer":      {"kind: google", "kind: google\n      issuer: https://evil.example.com"},
		"generic issuer missing":   {"kind: google", "kind: oidc"},
		"resource bounds":          {"cpu: 1000", "cpu: 0"},
		"replica bounds":           {"maxReplicas: 3", "maxReplicas: -1"},
		"negative relational cap":  {"maxReplicas: 3", "maxReplicas: 3\n      maxRelationalCapacityUnits: -1"},
		"nonfinite relational cap": {"maxReplicas: 3", "maxReplicas: 3\n      maxRelationalCapacityUnits: .inf"},
		"nan relational cap":       {"maxReplicas: 3", "maxReplicas: 3\n      maxRelationalCapacityUnits: .nan"},
		"execution mode":           {"[service, scheduled]", "[function]"},
		"missing route TLS":        {"publicExposure: false", "publicExposure: true"},
		"missing native identity":  {"workloadIdentityMode: native", "workloadIdentityMode: platform"},
		"repository query":         {"https://github.com/example/application", "https://github.com/example/application?token=secret-canary"},
		"repository traversal":     {"https://github.com/example/application", "https://github.com/example/../application"},
		"repository credentials":   {"https://github.com/example/application", "https://secret-canary@github.com/example/application"},
		"repository host mismatch": {"allowedSourceHosts: [github.com]", "allowedSourceHosts: [git.example.com]"},
		"reserved client":          {"id: remote-client", "id: apphub-cli"},
		"insecure redirect":        {"https://client.example.com/callback", "http://client.example.com/callback"},
	} {
		t.Run(name, func(t *testing.T) {
			contents := strings.Replace(validConfig, change[0], change[1], 1)
			_, err := serverconfig.Load(configFile(t, contents), serverconfig.ModeServe)
			if err == nil {
				t.Fatal("invalid operator policy accepted")
			}
			if strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("validation error exposed secret input")
			}
		})
	}
}

// The worker's own execution limits. Build isolation is deliberately absent:
// a build runs in a task the compute provider launches, so the builder image,
// the network it runs on and the cluster it runs in are checked by that
// provider's loader and by its runner's Validate, against the live substrate.
// Checking them here as well would be two places to change and neither
// authoritative.
func TestWorkerExecutionLimitsAreRequired(t *testing.T) {
	public := strings.Replace(validConfig, "      auth: githubApp\n      githubApp:\n        appId: 123\n        installationId: 456\n        privateKeyFile: ./unavailable-source.pem", "      auth: public", 1)
	for name, change := range map[string][2]string{
		"root workdir":     {"/var/lib/apphub/builds", "/"},
		"zero concurrency": {"worker:\n", "worker:\n  maxConcurrentDeployments: 0\n"},
		"stale heartbeat":  {"worker:\n", "worker:\n  staleAfter: 5s\n"},
		"zero timeout":     {"worker:\n", "worker:\n  deploymentTimeout: 0s\n"},
	} {
		t.Run(name, func(t *testing.T) {
			contents := strings.Replace(public, change[0], change[1], 1)
			if _, err := serverconfig.Load(configFile(t, contents), serverconfig.ModeWorker); err == nil {
				t.Fatal("unsafe worker configuration accepted")
			}
		})
	}
}

func TestSecretFilesAndEnvironmentFallback(t *testing.T) {
	filename := configFile(t, validConfig)
	t.Setenv("APPHUB_CONFIG", filename)
	if _, err := serverconfig.Load("", serverconfig.ModeServe); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{strings.Repeat("x", 31), strings.Repeat("x", 33), strings.Repeat("x", 32) + "\n"} {
		if err := os.WriteFile(filepath.Join(filepath.Dir(filename), "transaction.key"), []byte(key), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := serverconfig.Load(filename, serverconfig.ModeServe); err == nil {
			t.Fatal("wrong-sized transaction key accepted")
		}
	}
	if _, err := serverconfig.Load(filename, "unknown"); err == nil {
		t.Fatal("unknown command accepted")
	}
}

func TestProviderIdentityUniquenessAndCommandSecretOmission(t *testing.T) {
	for name, provider := range map[string]string{
		"duplicate id":            "    - id: google\n      label: Another\n      kind: oidc\n      issuer: https://issuer.example.com\n      clientId: another\n      clientSecretFile: ./client.secret\n      allowedDomains: [example.com]\n",
		"duplicate issuer client": "    - id: another\n      label: Another\n      kind: oidc\n      issuer: https://accounts.google.com\n      clientId: apphub\n      clientSecretFile: ./client.secret\n      allowedDomains: [example.com]\n",
	} {
		t.Run(name, func(t *testing.T) {
			contents := strings.Replace(validConfig, "  admins:\n", provider+"  admins:\n", 1)
			if _, err := serverconfig.Load(configFile(t, contents), serverconfig.ModeServe); err == nil {
				t.Fatal("ambiguous provider registry accepted")
			}
		})
	}
	serve := strings.Replace(validConfig, "        privateKeyFile: ./unavailable-source.pem\n", "", 1)
	serve = strings.Split(serve, "worker:\n")[0]
	if _, err := serverconfig.Load(configFile(t, serve), serverconfig.ModeServe); err != nil {
		t.Fatalf("serve required worker-only settings: %v", err)
	}
	worker := strings.Replace(validConfig, "  transactionKeyFile: ./transaction.key\n", "", 1)
	worker = strings.Replace(worker, "      clientSecretFile: ./client.secret\n", "", 1)
	worker = strings.Replace(worker, "      auth: githubApp\n      githubApp:\n        appId: 123\n        installationId: 456\n        privateKeyFile: ./unavailable-source.pem", "      auth: public", 1)
	if _, err := serverconfig.Load(configFile(t, worker), serverconfig.ModeWorker); err != nil {
		t.Fatalf("worker required serve-only secrets: %v", err)
	}
}

func TestServeReadsIDsAndSecretsFromTheEnvironment(t *testing.T) {
	const (
		clientID = "env-client-id"
		secret   = "env-client-secret-canary"
	)
	key := strings.Repeat("E", 32)
	contents := validConfig
	contents = strings.Replace(contents, "      clientId: apphub\n", "      clientIdEnv: APPHUB_AUTH_GOOGLE_CLIENT_ID\n", 1)
	contents = strings.Replace(contents, "      clientSecretFile: ./client.secret\n", "      clientSecretEnv: APPHUB_AUTH_GOOGLE_CLIENT_SECRET\n", 1)
	contents = strings.Replace(contents, "  transactionKeyFile: ./transaction.key\n", "  transactionKeyEnv: APPHUB_AUTH_TRANSACTION_KEY\n", 1)
	filename := configFile(t, contents)
	t.Setenv("APPHUB_AUTH_GOOGLE_CLIENT_ID", clientID)
	t.Setenv("APPHUB_AUTH_GOOGLE_CLIENT_SECRET", secret)
	t.Setenv("APPHUB_AUTH_TRANSACTION_KEY", base64.StdEncoding.EncodeToString([]byte(key)))

	c, err := serverconfig.Load(filename, serverconfig.ModeServe)
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth.Providers[0].ClientID != clientID {
		t.Fatalf("client id = %q, want the environment value", c.Auth.Providers[0].ClientID)
	}
	if credentials.Reveal(c.Auth.Providers[0].ClientSecret) != secret {
		t.Fatal("client secret was not loaded from the environment")
	}
	if credentials.Reveal(c.Auth.TransactionKey) != key {
		t.Fatal("transaction key was not loaded from the environment")
	}
	assertNoSecrets(t, c, secret, key)
}

func TestWorkerReadsGitHubAppIDsAndKeyFromTheEnvironment(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	contents := validConfig
	contents = strings.Replace(contents, "  transactionKeyFile: ./transaction.key\n", "", 1)
	contents = strings.Replace(contents, "      clientSecretFile: ./client.secret\n", "", 1)
	contents = strings.Replace(contents, "        appId: 123\n        installationId: 456\n        privateKeyFile: ./unavailable-source.pem",
		"        appIdEnv: APPHUB_SOURCE_EXAMPLE_APP_ID\n        installationIdEnv: APPHUB_SOURCE_EXAMPLE_INSTALLATION_ID\n        privateKeyEnv: APPHUB_SOURCE_EXAMPLE_PRIVATE_KEY", 1)
	filename := configFile(t, contents)
	t.Setenv("APPHUB_SOURCE_EXAMPLE_APP_ID", "123")
	t.Setenv("APPHUB_SOURCE_EXAMPLE_INSTALLATION_ID", "456")
	t.Setenv("APPHUB_SOURCE_EXAMPLE_PRIVATE_KEY", string(encoded))

	c, err := serverconfig.Load(filename, serverconfig.ModeWorker)
	if err != nil {
		t.Fatal(err)
	}
	g := c.Source.Repositories[0].GitHubApp
	if g.AppID != 123 || g.InstallationID != 456 {
		t.Fatalf("github app ids = %d/%d, want 123/456", g.AppID, g.InstallationID)
	}
	if credentials.Reveal(g.PrivateKey) != string(encoded) {
		t.Fatal("source key was not loaded from the environment")
	}
	assertNoSecrets(t, c, "BEGIN RSA PRIVATE KEY", string(encoded))
}

func TestInlineAndEnvironmentIDsTogetherAreRefused(t *testing.T) {
	contents := strings.Replace(validConfig, "      clientId: apphub\n", "      clientId: apphub\n      clientIdEnv: APPHUB_AUTH_GOOGLE_CLIENT_ID\n", 1)
	t.Setenv("APPHUB_AUTH_GOOGLE_CLIENT_ID", "other")
	if _, err := serverconfig.Load(configFile(t, contents), serverconfig.ModeServe); err == nil {
		t.Fatal("clientId and clientIdEnv together were accepted")
	}
}

func TestServeLoadsTheWebhookSecretFromTheEnvironment(t *testing.T) {
	const secret = "webhook-secret-canary"
	contents := validConfig + "github:\n  webhookSecretEnv: APPHUB_GITHUB_WEBHOOK_SECRET\n"
	t.Setenv("APPHUB_GITHUB_WEBHOOK_SECRET", secret+"\n")
	c, err := serverconfig.Load(configFile(t, contents), serverconfig.ModeServe)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Reveal(c.GitHub.WebhookSecret) != secret {
		t.Fatal("webhook secret was not loaded from the environment")
	}
	assertNoSecrets(t, c, secret)
}

func TestWorkerDoesNotLoadTheWebhookSecret(t *testing.T) {
	contents := validConfig + "github:\n  webhookSecretEnv: APPHUB_GITHUB_WEBHOOK_SECRET\n"
	contents = strings.ReplaceAll(contents, "transaction.key", "missing-transaction.key")
	contents = strings.ReplaceAll(contents, "client.secret", "missing-client.secret")
	contents = strings.ReplaceAll(contents, "unavailable-source.pem", "source.pem")
	contents = strings.ReplaceAll(contents, "listenAddress: 127.0.0.1:8080\nstaticDir: dist\n", "")
	filename := configFile(t, contents)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err := os.WriteFile(filepath.Join(filepath.Dir(filename), "source.pem"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APPHUB_GITHUB_WEBHOOK_SECRET", "webhook-secret-canary")
	c, err := serverconfig.Load(filename, serverconfig.ModeWorker)
	if err != nil {
		t.Fatal(err)
	}
	if !c.GitHub.WebhookSecret.IsZero() {
		t.Fatal("worker loaded the webhook secret")
	}
}

func TestWebhookSecretReferenceMustBeOneForm(t *testing.T) {
	both := validConfig + "github:\n  webhookSecretFile: ./webhook.secret\n  webhookSecretEnv: APPHUB_GITHUB_WEBHOOK_SECRET\n"
	if _, err := serverconfig.Load(configFile(t, both), serverconfig.ModeServe); err == nil {
		t.Fatal("webhookSecretFile and webhookSecretEnv together were accepted")
	}
	missing := validConfig + "github:\n  webhookSecretEnv: APPHUB_GITHUB_WEBHOOK_SECRET\n"
	t.Setenv("APPHUB_GITHUB_WEBHOOK_SECRET", "")
	if _, err := serverconfig.Load(configFile(t, missing), serverconfig.ModeServe); err == nil {
		t.Fatal("unset webhookSecretEnv was accepted")
	}
}

func TestUnsetEnvironmentIDFailsClosed(t *testing.T) {
	contents := strings.Replace(validConfig, "      clientId: apphub\n", "      clientIdEnv: APPHUB_AUTH_GOOGLE_CLIENT_ID\n", 1)
	t.Setenv("APPHUB_AUTH_GOOGLE_CLIENT_ID", "")
	if _, err := serverconfig.Load(configFile(t, contents), serverconfig.ModeServe); err == nil {
		t.Fatal("unset clientIdEnv was accepted")
	}
}

func TestEmptySourceRepositoriesAreValid(t *testing.T) {
	contents := strings.Replace(validConfig, `source:
  repositories:
    - url: https://github.com/example/application
      auth: githubApp
      githubApp:
        appId: 123
        installationId: 456
        privateKeyFile: ./unavailable-source.pem
`, `source:
  repositories: []
`, 1)
	for _, mode := range []string{serverconfig.ModeServe, serverconfig.ModeWorker} {
		if _, err := serverconfig.Load(configFile(t, contents), mode); err != nil {
			t.Fatalf("%s: empty source.repositories rejected: %v", mode, err)
		}
	}
}
