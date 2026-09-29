// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package serverconfig

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/modules/deploy"
)

var (
	stableID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	// envName is the spelling ECS and POSIX agree on. YAML names the variable;
	// the value never belongs in the document.
	envName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,255}$`)
)

// Load uses APPHUB_CONFIG only when path is empty. Errors identify the invalid
// field, never echo YAML values, parser errors, file contents or secret paths.
// Discovery, AWS capability validation and runtime isolation preflight belong to
// their respective constructors; this loader makes no network requests.
func Load(configPath, mode string) (Config, error) {
	if mode != ModeServe && mode != ModeWorker {
		return Config{}, invalid("mode", "must be serve or worker")
	}
	if configPath == "" {
		configPath = os.Getenv("APPHUB_CONFIG")
	}
	if configPath == "" {
		return Config{}, invalid("config", "path is required")
	}
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		return Config{}, invalid("config", "path is invalid")
	}
	data, err := readFile(absolute, 1<<20)
	if err != nil {
		return Config{}, invalid("config", "cannot read bounded regular file")
	}
	c := Config{Worker: WorkerConfig{
		MaxConcurrentDeployments: 2, DeploymentTimeout: 30 * time.Minute, TeardownTimeout: 60 * time.Minute,
		HeartbeatInterval: 10 * time.Second, StaleAfter: 60 * time.Second,
	}}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&c); err != nil {
		return Config{}, invalid("config", "invalid YAML or unknown field")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, invalid("config", "exactly one YAML document is required")
	}
	if err := c.resolveEnv(); err != nil {
		return Config{}, err
	}
	if err := c.validate(mode); err != nil {
		return Config{}, err
	}
	c.resolveFiles(filepath.Dir(absolute))
	if err := c.loadSecrets(mode); err != nil {
		return Config{}, err
	}
	return c, nil
}

func invalid(field, reason string) error { return fmt.Errorf("serverconfig: %s: %s", field, reason) }

// canonicalPublicOrigin requires the spelling a browser sends in Origin. It
// deliberately rejects rather than rewrites configuration: OAuth issuer and
// redirect construction must use the same origin as exact CSRF comparisons.
// This restriction does not apply to upstream OIDC issuer identifiers.
func canonicalPublicOrigin(raw string, allowLoopback bool) bool {
	u, err := parseURL(raw, allowLoopback, true)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if address, err := netip.ParseAddr(host); err == nil {
		host = address.String()
		if address.Is6() {
			if address.Is4In6() {
				// Browsers serialize IPv4-mapped IPv6 in hexadecimal, unlike
				// netip's dotted-decimal rendering of the last 32 bits.
				octets := address.As16()
				host = fmt.Sprintf("::ffff:%x:%x", uint16(octets[12])<<8|uint16(octets[13]), uint16(octets[14])<<8|uint16(octets[15]))
			}
			host = "[" + host + "]"
		}
	} else {
		host = strings.ToLower(host)
		last := host[strings.LastIndexByte(host, '.')+1:]
		// WHATWG treats a final numeric label as an IPv4 address, including
		// abbreviated, octal and hexadecimal forms netip correctly refuses.
		// Only canonical dotted-decimal IPv4 reaches the branch above.
		if strings.Trim(last, "0123456789") == "" || (strings.HasPrefix(last, "0x") && strings.Trim(last[2:], "0123456789abcdef") == "") {
			return false
		}
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || strconv.Itoa(n) != port || (u.Scheme == "https" && n == 443) || (u.Scheme == "http" && n == 80) {
			return false
		}
		host += ":" + port
	}
	return raw == u.Scheme+"://"+host
}

func (c *Config) validate(mode string) error {
	if !canonicalPublicOrigin(c.PublicOrigin, c.Auth.AllowLoopbackHTTP) {
		return invalid("publicOrigin", "must be a canonical HTTPS origin (lowercase host, no default or padded port; HTTP requires explicitly allowed literal loopback)")
	}
	if mode == ModeServe {
		host, port, err := net.SplitHostPort(c.ListenAddress)
		if err != nil || !validPort(port) || (host != "" && net.ParseIP(host) == nil && !validDomain(host)) {
			return invalid("listenAddress", "must be a host and positive port")
		}
		if strings.TrimSpace(c.StaticDir) == "" {
			return invalid("staticDir", "is required")
		}
	}
	if strings.TrimSpace(c.Store.Region) == "" || strings.TrimSpace(c.Store.TableName) == "" {
		return invalid("store", "region and tableName are required")
	}
	if c.Store.AuditTableName == "" {
		c.Store.AuditTableName = c.Store.TableName + "-audit"
	}
	if c.Store.AuditTableName == c.Store.TableName {
		return invalid("store.auditTableName", "must be a separate table")
	}
	if c.Store.Endpoint != "" {
		if _, err := parseURL(c.Store.Endpoint, c.Auth.AllowLoopbackHTTP, true); err != nil {
			return invalid("store.endpoint", "must be an HTTPS origin or explicitly allowed literal loopback HTTP")
		}
	}
	if err := c.validateAuth(mode); err != nil {
		return err
	}
	if err := c.validateSource(mode); err != nil {
		return err
	}
	if err := c.validateTargets(); err != nil {
		return err
	}
	if err := c.validateObservability(); err != nil {
		return err
	}
	if err := c.validateGitHub(); err != nil {
		return err
	}
	if arn := c.Secrets.HandoffKMSKeyARN; arn != "" && (!strings.HasPrefix(arn, "arn:") || !strings.Contains(arn, ":kms:")) {
		return invalid("secrets.handoffKmsKeyArn", "must be a KMS key or alias ARN")
	}
	if mode == ModeWorker {
		return c.validateWorker()
	}
	return nil
}

// validateGitHub checks the webhook secret reference. The value is loaded
// only in serve mode; naming the variable here must not make the worker,
// which is never injected with the secret, fail to start.
func (c *Config) validateGitHub() error {
	c.GitHub.WebhookSecretFile = strings.TrimSpace(c.GitHub.WebhookSecretFile)
	c.GitHub.WebhookSecretEnv = strings.TrimSpace(c.GitHub.WebhookSecretEnv)
	file := c.GitHub.WebhookSecretFile
	env := c.GitHub.WebhookSecretEnv
	if file != "" && env != "" {
		return invalid("github", "set webhookSecretFile or webhookSecretEnv, not both")
	}
	if env != "" && !envName.MatchString(env) {
		return invalid("github.webhookSecretEnv", "must be an environment variable name")
	}
	return nil
}

// validateObservability requires AWSRegion and a nonempty LogGroups together,
// with unique, nonempty display names: a half-configured admin surface is a
// deployment nobody reviewed, not "disabled".
func (c *Config) validateObservability() error {
	o := c.Observability
	region := strings.TrimSpace(o.AWSRegion)
	if region == "" && len(o.LogGroups) == 0 {
		return nil
	}
	if region == "" || len(o.LogGroups) == 0 {
		return invalid("observability", "awsRegion and a nonempty logGroups are required together, or both left empty to disable")
	}
	seen := make(map[string]bool, len(o.LogGroups))
	for i, g := range o.LogGroups {
		field := fmt.Sprintf("observability.logGroups[%d]", i)
		name := strings.TrimSpace(g.Name)
		if name == "" || len(name) > 63 || strings.ContainsFunc(name, unicode.IsControl) {
			return invalid(field+".name", "must be a short nonempty display name")
		}
		if seen[name] {
			return invalid(field+".name", "duplicate display name")
		}
		seen[name] = true
		if strings.TrimSpace(g.LogGroup) == "" || len(g.LogGroup) > 512 || strings.ContainsFunc(g.LogGroup, unicode.IsControl) {
			return invalid(field+".logGroup", "must be a nonempty CloudWatch log group name")
		}
	}
	return nil
}

func (c *Config) validateAuth(mode string) error {
	if len(c.Auth.Providers) == 0 {
		return invalid("auth.providers", "at least one admitted provider is required")
	}
	if mode == ModeServe {
		file := strings.TrimSpace(c.Auth.TransactionKeyFile)
		env := strings.TrimSpace(c.Auth.TransactionKeyEnv)
		if file != "" && env != "" {
			return invalid("auth", "set transactionKeyFile or transactionKeyEnv, not both")
		}
		if file == "" && env == "" {
			return invalid("auth.transactionKeyFile", "transactionKeyFile or transactionKeyEnv is required for serve")
		}
		if env != "" && !envName.MatchString(env) {
			return invalid("auth.transactionKeyEnv", "must be an environment variable name")
		}
	}
	ids, issuerClients := map[string]bool{}, map[string]bool{}
	for i := range c.Auth.Providers {
		p := &c.Auth.Providers[i]
		field := fmt.Sprintf("auth.providers[%d]", i)
		if !stableID.MatchString(p.ID) || ids[p.ID] {
			return invalid(field+".id", "must be a unique stable identifier")
		}
		ids[p.ID] = true
		if strings.TrimSpace(p.Label) == "" || strings.TrimSpace(p.ClientID) == "" {
			return invalid(field, "label and clientId or clientIdEnv are required")
		}
		switch p.Kind {
		case "google":
			if p.Issuer != "" && p.Issuer != "https://accounts.google.com" {
				return invalid(field+".issuer", "Google uses its fixed HTTPS issuer")
			}
			p.Issuer = "https://accounts.google.com"
		case "oidc":
			if _, err := parseURL(p.Issuer, c.Auth.AllowLoopbackHTTP, false); err != nil {
				return invalid(field+".issuer", "must be a secure issuer URL")
			}
		default:
			return invalid(field+".kind", "must be google or oidc")
		}
		key := p.Issuer + "\x00" + p.ClientID
		if issuerClients[key] {
			return invalid(field, "duplicate issuer and client configuration")
		}
		issuerClients[key] = true
		if mode == ModeServe {
			file := strings.TrimSpace(p.ClientSecretFile)
			env := strings.TrimSpace(p.ClientSecretEnv)
			if file != "" && env != "" {
				return invalid(field, "set clientSecretFile or clientSecretEnv, not both")
			}
			if file == "" && env == "" {
				return invalid(field+".clientSecretFile", "clientSecretFile or clientSecretEnv is required for serve")
			}
			if env != "" && !envName.MatchString(env) {
				return invalid(field+".clientSecretEnv", "must be an environment variable name")
			}
		}
		if len(p.AllowedEmails)+len(p.AllowedDomains) == 0 {
			return invalid(field, "an exact email or domain admission rule is required")
		}
		for j, email := range p.AllowedEmails {
			normalized, _, ok := normalizeEmail(email)
			if !ok {
				return invalid(field+".allowedEmails", "must contain email addresses without wildcards or display names")
			}
			p.AllowedEmails[j] = normalized
		}
		for j, domain := range p.AllowedDomains {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if !validDomain(domain) {
				return invalid(field+".allowedDomains", "must contain exact DNS domains without wildcards")
			}
			p.AllowedDomains[j] = domain
		}
	}
	admins := map[string]bool{}
	for i, a := range c.Auth.Admins {
		key := a.ProviderID + "\x00" + a.Subject
		if !ids[a.ProviderID] || strings.TrimSpace(a.Subject) == "" || hasControls(a.Subject) || admins[key] {
			return invalid(fmt.Sprintf("auth.admins[%d]", i), "requires a known provider and unique nonempty exact subject")
		}
		admins[key] = true
	}
	clients := map[string]bool{"apphub-cli": true}
	for i, client := range c.Auth.Clients {
		field := fmt.Sprintf("auth.clients[%d]", i)
		if strings.TrimSpace(client.ID) == "" || hasControls(client.ID) || clients[client.ID] {
			return invalid(field+".id", "must be unique; apphub-cli is reserved")
		}
		clients[client.ID] = true
		if len(client.RedirectURIs) == 0 {
			return invalid(field+".redirectUris", "at least one exact HTTPS redirect is required")
		}
		redirects := map[string]bool{}
		for _, redirect := range client.RedirectURIs {
			if !validRedirect(redirect) || redirects[redirect] {
				return invalid(field+".redirectUris", "must contain unique exact HTTPS redirects without userinfo or fragment")
			}
			redirects[redirect] = true
		}
	}
	return nil
}

func (c *Config) validateSource(mode string) error {
	// Empty is valid: the Workspace GitHub App installation is then the
	// deploy allowlist. Entries that are present are still an extra restrictor
	// and must be exact canonical URLs.
	seen := map[string]bool{}
	for i := range c.Source.Repositories {
		r := &c.Source.Repositories[i]
		field := fmt.Sprintf("source.repositories[%d]", i)
		u, err := parseURL(r.URL, false, false)
		if err != nil {
			return invalid(field+".url", "must be an exact HTTPS repository URL")
		}
		canonical, err := deploy.ValidateSourceURL(r.URL, []string{u.Hostname()})
		if err != nil || u.Path == "" || u.Path == "/" || u.RawPath != "" || path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/") {
			return invalid(field+".url", "must name a canonical repository without query, fragment or escaped path")
		}
		if seen[canonical] {
			return invalid(field+".url", "duplicate repository")
		}
		seen[canonical] = true
		r.URL = canonical
		switch r.Auth {
		case "public":
			if r.GitHubApp != nil {
				return invalid(field+".githubApp", "is not valid for public repositories")
			}
		case "githubApp":
			g := r.GitHubApp
			if g == nil || g.AppID <= 0 || g.InstallationID <= 0 {
				return invalid(field+".githubApp", "positive appId or appIdEnv and installationId or installationIdEnv are required")
			}
			if u.Hostname() != "github.com" || len(strings.Split(strings.Trim(u.Path, "/"), "/")) != 2 {
				return invalid(field+".url", "GitHub App repositories must name github.com owner/repository")
			}
			if mode == ModeWorker {
				file := strings.TrimSpace(g.PrivateKeyFile)
				env := strings.TrimSpace(g.PrivateKeyEnv)
				if file != "" && env != "" {
					return invalid(field+".githubApp", "set privateKeyFile or privateKeyEnv, not both")
				}
				if file == "" && env == "" {
					return invalid(field+".githubApp.privateKeyFile", "privateKeyFile or privateKeyEnv is required for worker")
				}
				if env != "" && !envName.MatchString(env) {
					return invalid(field+".githubApp.privateKeyEnv", "must be an environment variable name")
				}
			}
		default:
			return invalid(field+".auth", "must be public or githubApp")
		}
	}
	return nil
}

func (c Config) validateTargets() error {
	if len(c.Targets) == 0 {
		return invalid("targets", "at least one operator target is required")
	}
	for id, target := range c.Targets {
		// IDs are operator input too: do not interpolate them into diagnostics.
		if !stableID.MatchString(id) {
			return invalid("targets", "keys must be stable identifiers")
		}
		if strings.TrimSpace(target.Label) == "" || strings.TrimSpace(target.AWSConfigFile) == "" {
			return invalid("targets", "each target requires label and awsConfigFile")
		}
		d := target.Deployment
		if err := target.DeployConfig().Validate(); err != nil {
			return invalid("targets.deployConfig", "invalid deployment configuration; resourcePrefix and allowedSourceHosts are required")
		}
		if d.WorkloadIdentityMode != "native" {
			return invalid("targets.deployConfig.workloadIdentityMode", "hosted AWS targets must explicitly select native")
		}
		if strings.TrimSpace(d.Placement.Name) == "" {
			return invalid("targets.deployConfig.placement.name", "an explicit operator placement is required")
		}
		for _, host := range d.AllowedSourceHosts {
			if !validDomain(host) || host != strings.ToLower(host) {
				return invalid("targets.deployConfig.allowedSourceHosts", "must contain exact lowercase DNS hosts")
			}
		}
		for _, repository := range c.Source.Repositories {
			if _, err := deploy.ValidateSourceURL(repository.URL, d.AllowedSourceHosts); err != nil {
				return invalid("targets.deployConfig.allowedSourceHosts", "must allow the configured repositories")
			}
		}
		policy := target.Policy
		if len(policy.ResourceSizes) == 0 || policy.MaxReplicas <= 0 || len(policy.ExecutionModes) == 0 {
			return invalid("targets.policy", "nonempty resourceSizes/executionModes and positive maxReplicas are required")
		}
		if policy.MaxRelationalCapacityUnits < 0 || math.IsNaN(policy.MaxRelationalCapacityUnits) || math.IsInf(policy.MaxRelationalCapacityUnits, 0) {
			return invalid("targets.policy.maxRelationalCapacityUnits", "must be a finite nonnegative capacity-unit ceiling (zero uses the default)")
		}
		sizes := map[ResourceSize]bool{}
		for _, size := range policy.ResourceSizes {
			if size.CPU <= 0 || size.Memory <= 0 || sizes[size] {
				return invalid("targets.policy.resourceSizes", "must contain distinct positive CPU millicores and memory MiB pairs")
			}
			sizes[size] = true
		}
		modes := map[deploy.ExecutionMode]bool{}
		for _, mode := range policy.ExecutionModes {
			if (mode != deploy.ExecutionService && mode != deploy.ExecutionScheduled) || modes[mode] {
				return invalid("targets.policy.executionModes", "must contain distinct service or scheduled modes")
			}
			modes[mode] = true
		}
		if policy.PublicExposure && (!validDomain(d.RouteDomain) || strings.TrimSpace(d.RouteCertificate) == "") {
			return invalid("targets.deployConfig", "public exposure requires an exact routeDomain and routeCertificate")
		}
		if (d.InternalRouteDomain != "") != (strings.TrimSpace(d.InternalRouteCertificate) != "") || (d.InternalRouteDomain != "" && !validDomain(d.InternalRouteDomain)) {
			return invalid("targets.deployConfig", "internal exposure requires both an exact internalRouteDomain and internalRouteCertificate")
		}
	}
	return nil
}

func (c Config) validateWorker() error {
	w := c.Worker
	// Nothing here validates the builder image or the network it runs on. A
	// build runs in a task the compute provider launches, so both are the
	// provider's configuration, checked at parse time by its own loader and
	// against the live substrate by its runner's Validate. Duplicating them
	// here would be two places to change and one of them authoritative.
	if !filepath.IsAbs(w.WorkDir) || filepath.Clean(w.WorkDir) != w.WorkDir || w.WorkDir == "/" {
		return invalid("worker.workDir", "must be a dedicated absolute directory")
	}
	if w.MaxConcurrentDeployments <= 0 {
		return invalid("worker.maxConcurrentDeployments", "must be positive")
	}
	if w.DeploymentTimeout <= 0 || w.TeardownTimeout <= w.HeartbeatInterval || w.HeartbeatInterval <= 0 || w.StaleAfter <= w.HeartbeatInterval || w.DeploymentTimeout <= w.HeartbeatInterval {
		return invalid("worker", "timeouts must be positive, with staleAfter, deploymentTimeout and teardownTimeout greater than heartbeatInterval")
	}
	return nil
}

func (c *Config) resolveFiles(base string) {
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	c.StaticDir = resolve(c.StaticDir)
	c.Auth.TransactionKeyFile = resolve(c.Auth.TransactionKeyFile)
	for i := range c.Auth.Providers {
		c.Auth.Providers[i].ClientSecretFile = resolve(c.Auth.Providers[i].ClientSecretFile)
	}
	for id, target := range c.Targets {
		target.AWSConfigFile = resolve(target.AWSConfigFile)
		c.Targets[id] = target
	}
	for i := range c.Source.Repositories {
		if g := c.Source.Repositories[i].GitHubApp; g != nil {
			g.PrivateKeyFile = resolve(g.PrivateKeyFile)
		}
	}
	c.GitHub.WebhookSecretFile = resolve(c.GitHub.WebhookSecretFile)
}

func (c *Config) loadSecrets(mode string) error {
	if mode == ModeServe {
		key, err := loadTransactionKey(c.Auth)
		if err != nil {
			return err
		}
		c.Auth.TransactionKey = credentials.NewSecret(string(key))
		for i := range c.Auth.Providers {
			p := &c.Auth.Providers[i]
			secret, err := loadBoundedSecret(p.ClientSecretFile, p.ClientSecretEnv, fmt.Sprintf("auth.providers[%d]", i), 64<<10)
			if err != nil {
				return err
			}
			p.ClientSecret = secret
		}
		return c.loadGitHubWebhookSecret()
	}
	for i := range c.Source.Repositories {
		g := c.Source.Repositories[i].GitHubApp
		if g == nil {
			continue
		}
		data, err := readSecretBytes(g.PrivateKeyFile, g.PrivateKeyEnv, 64<<10)
		if err != nil || !validRSAKey(data) {
			field := "privateKeyFile"
			if strings.TrimSpace(g.PrivateKeyEnv) != "" {
				field = "privateKeyEnv"
			}
			return invalid(fmt.Sprintf("source.repositories[%d].githubApp.%s", i, field), "must contain a valid RSA private key PEM")
		}
		g.PrivateKey = credentials.NewSecret(string(data))
	}
	return nil
}

// resolveEnv fills inline ID fields from the environment variables YAML named.
// It never copies secret material: those stay in loadSecrets. Errors name the
// field, never the value.
func (c *Config) resolveEnv() error {
	for i := range c.Auth.Providers {
		p := &c.Auth.Providers[i]
		field := fmt.Sprintf("auth.providers[%d]", i)
		id, err := resolveString(p.ClientID, p.ClientIDEnv, field+".clientId", field+".clientIdEnv")
		if err != nil {
			return err
		}
		p.ClientID = id
	}
	for i := range c.Source.Repositories {
		g := c.Source.Repositories[i].GitHubApp
		if g == nil {
			continue
		}
		field := fmt.Sprintf("source.repositories[%d].githubApp", i)
		appID, err := resolveInt64(g.AppID, g.AppIDEnv, field+".appId", field+".appIdEnv")
		if err != nil {
			return err
		}
		g.AppID = appID
		instID, err := resolveInt64(g.InstallationID, g.InstallationIDEnv, field+".installationId", field+".installationIdEnv")
		if err != nil {
			return err
		}
		g.InstallationID = instID
	}
	return nil
}

func resolveString(inline, envField, inlineName, envNameField string) (string, error) {
	inline = strings.TrimSpace(inline)
	envField = strings.TrimSpace(envField)
	if inline != "" && envField != "" {
		return "", invalid(inlineName, "set the value or the environment variable name, not both")
	}
	if envField == "" {
		return inline, nil
	}
	if !envName.MatchString(envField) {
		return "", invalid(envNameField, "must be an environment variable name")
	}
	value := strings.TrimSpace(os.Getenv(envField))
	if value == "" {
		return "", invalid(envNameField, "is unset or empty")
	}
	return value, nil
}

func resolveInt64(inline int64, envField, inlineName, envNameField string) (int64, error) {
	envField = strings.TrimSpace(envField)
	if inline > 0 && envField != "" {
		return 0, invalid(inlineName, "set the value or the environment variable name, not both")
	}
	if envField == "" {
		return inline, nil
	}
	if !envName.MatchString(envField) {
		return 0, invalid(envNameField, "must be an environment variable name")
	}
	raw := strings.TrimSpace(os.Getenv(envField))
	if raw == "" {
		return 0, invalid(envNameField, "is unset or empty")
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return 0, invalid(envNameField, "must be a positive integer")
	}
	return n, nil
}

func loadTransactionKey(auth AuthConfig) ([]byte, error) {
	if env := strings.TrimSpace(auth.TransactionKeyEnv); env != "" {
		raw := strings.TrimSpace(os.Getenv(env))
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(decoded) != 32 {
			return nil, invalid("auth.transactionKeyEnv", "must contain base64 of exactly 32 raw bytes")
		}
		return decoded, nil
	}
	key, err := readFile(auth.TransactionKeyFile, 32)
	if err != nil || len(key) != 32 {
		return nil, invalid("auth.transactionKeyFile", "must contain exactly 32 raw bytes")
	}
	return key, nil
}

// maxWebhookSecretBytes is the longest HMAC secret serve will load. A
// 32-byte key encoded as standard base64 is 44 characters; the bound leaves
// room for a longer operator-chosen secret without accepting an unbounded
// environment value.
const maxWebhookSecretBytes = 256

func (c *Config) loadGitHubWebhookSecret() error {
	file := strings.TrimSpace(c.GitHub.WebhookSecretFile)
	env := strings.TrimSpace(c.GitHub.WebhookSecretEnv)
	if file == "" && env == "" {
		return nil
	}
	data, err := readSecretBytes(file, env, 1024)
	which := "webhookSecretFile"
	if env != "" {
		which = "webhookSecretEnv"
	}
	secret := strings.TrimSpace(string(data))
	if err != nil || secret == "" || len(secret) > maxWebhookSecretBytes {
		return invalid("github."+which, "cannot read a nonempty bounded secret")
	}
	c.GitHub.WebhookSecret = credentials.NewSecret(secret)
	return nil
}

func loadBoundedSecret(file, env, field string, limit int64) (credentials.Secret, error) {
	data, err := readSecretBytes(file, env, limit)
	which := "clientSecretFile"
	if strings.TrimSpace(env) != "" {
		which = "clientSecretEnv"
	}
	if err != nil || strings.TrimSpace(string(data)) == "" {
		return credentials.Secret{}, invalid(field+"."+which, "cannot read a nonempty bounded secret")
	}
	return credentials.NewSecret(strings.TrimSpace(string(data))), nil
}

func readSecretBytes(file, env string, limit int64) ([]byte, error) {
	if name := strings.TrimSpace(env); name != "" {
		raw := os.Getenv(name)
		if strings.TrimSpace(raw) == "" || int64(len(raw)) > limit {
			return nil, errors.New("invalid secret")
		}
		return []byte(raw), nil
	}
	return readFile(file, limit)
}

func readFile(filename string, limit int64) ([]byte, error) {
	info, err := os.Stat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid file")
	}
	// #nosec G304 -- Only operator-selected config and mounted-secret paths reach
	// this loader, never HTTP input; regular-file and byte bounds are enforced.
	f, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("unreadable file")
	}
	defer func() { _ = f.Close() }() // Read-only descriptor cleanup cannot change the read result.
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("invalid file size")
	}
	return data, nil
}

func validRSAKey(data []byte) bool {
	block, rest := pem.Decode(data)
	if block == nil || strings.TrimSpace(string(rest)) != "" {
		return false
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return false
		}
		key = parsed
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return false
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return false
		}
	default:
		return false
	}
	return key.Validate() == nil
}

func hasControls(value string) bool { return strings.ContainsFunc(value, unicode.IsControl) }

func normalizeEmail(value string) (string, string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	local, domain, ok := strings.Cut(value, "@")
	if !ok || local == "" || strings.ContainsAny(local, " \t\r\n<>(),;:\\\"[]*") || hasControls(local) || !validDomain(domain) {
		return "", "", false
	}
	return value, domain, true
}

func validDomain(host string) bool {
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

func validPort(port string) bool {
	if port == "" {
		return false
	}
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	value, err := strconv.Atoi(port)
	return err == nil && value > 0 && value <= 65535
}

func parseURL(raw string, allowLoopback, origin bool) (*url.URL, error) {
	bad := errors.New("invalid URL")
	if raw == "" || strings.TrimSpace(raw) != raw || hasControls(raw) || strings.ContainsAny(raw, "\\#?") {
		return nil, bad
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return nil, bad
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil && !validDomain(host) {
		return nil, bad
	}
	if strings.HasSuffix(u.Host, ":") || (u.Port() != "" && !validPort(u.Port())) {
		return nil, bad
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !allowLoopback || ip == nil || !ip.IsLoopback()) {
		return nil, bad
	}
	if origin && (u.Path != "" || u.RawPath != "") {
		return nil, bad
	}
	if hasControls(u.Path) || strings.Contains(u.Path, "\\") {
		return nil, bad
	}
	return u, nil
}

func validRedirect(raw string) bool {
	if strings.TrimSpace(raw) != raw || hasControls(raw) || strings.ContainsAny(raw, "\\#") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	// A registered redirect may have a fixed query. It is still matched as the
	// original exact string by OAuth; stripping here only reuses URL validation.
	u.RawQuery, u.ForceQuery = "", false
	_, err = parseURL(u.String(), false, false)
	return err == nil
}
