// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package serverconfig loads operator policy without constructing cloud providers.
package serverconfig

import (
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/modules/deploy"
)

// Command modes determine which mounted secrets Load may read.
const (
	ModeServe  = "serve"
	ModeWorker = "worker"
)

// Config is operator-owned. Load validates policy for both processes but reads
// only the secrets belonging to the selected command. Relative file references
// resolve against the configuration file's directory, not the process directory.
type Config struct {
	PublicOrigin  string                  `yaml:"publicOrigin" json:"publicOrigin"`
	ListenAddress string                  `yaml:"listenAddress" json:"listenAddress"`
	StaticDir     string                  `yaml:"staticDir" json:"staticDir"`
	Auth          AuthConfig              `yaml:"auth" json:"auth"`
	Store         StoreConfig             `yaml:"store" json:"store"`
	Targets       map[string]TargetConfig `yaml:"targets" json:"targets"`
	Source        SourceConfig            `yaml:"source" json:"source"`
	Worker        WorkerConfig            `yaml:"worker" json:"worker"`
	// Observability, when set, lets an administrator read operator-named
	// CloudWatch log groups from the Workspace UI. Optional: unset disables
	// that admin surface entirely.
	Observability ObservabilityConfig `yaml:"observability" json:"observability"`
	// GitHub names how serve checks an inbound GitHub App webhook. Optional:
	// with neither secret reference set, every delivery is rejected. The
	// worker never loads the secret. The YAML holds the variable or file
	// name, never the value.
	GitHub GitHubWebhookConfig `yaml:"github" json:"github"`
	// Secrets enables application secrets. Optional: unset leaves them
	// read-only in the portal and refuses changes.
	Secrets SecretsConfig `yaml:"secrets" json:"secrets"`
	// Traffic enables per-application request counts from the ingress
	// access log. Optional: unset reports traffic as not collected.
	Traffic TrafficConfig `yaml:"traffic" json:"traffic"`
}

// TrafficConfig names the ingress access-log group the worker counts
// requests from. serve reads it only to say whether collection is on.
type TrafficConfig struct {
	// LogGroup is the CloudWatch Logs group name (not ARN) Traefik writes
	// JSON access logs to.
	LogGroup string `yaml:"logGroup" json:"logGroup"`
	// Region defaults to store.region.
	Region string `yaml:"region" json:"region"`
}

// SecretsConfig names the KMS key that carries application secret values
// from serve to the worker. serve may only encrypt under it and the worker
// may only decrypt; both processes read the same ARN. It is not the key SSM
// encrypts the stored parameters with.
type SecretsConfig struct {
	HandoffKMSKeyARN string `yaml:"handoffKmsKeyArn" json:"handoffKmsKeyArn"`
}

// The admin-managed GitHub App's private key location is not configured
// here: cmd/apphub derives it automatically from PublicOrigin/Store (see
// githubAppKeyLocation) so that turning that Workspace surface on never
// requires an operator config change or a redeploy. The key itself is never
// held in this struct, in the database, or in any YAML regardless.
//
// The webhook HMAC secret is separate. It is not a source credential: serve
// needs it to check X-Hub-Signature-256, and ECS injects it the same way as
// the transaction key. GitHubWebhookConfig names that variable.

// GitHubWebhookConfig is the inbound GitHub App webhook. Exactly one of
// WebhookSecretFile or WebhookSecretEnv may be set; neither means the
// receiver fails closed. The loaded secret belongs only to serve.
type GitHubWebhookConfig struct {
	WebhookSecretFile string             `yaml:"webhookSecretFile" json:"webhookSecretFile"`
	WebhookSecretEnv  string             `yaml:"webhookSecretEnv" json:"webhookSecretEnv"`
	WebhookSecret     credentials.Secret `yaml:"-" json:"-"`
}

// ObservabilityConfig names the CloudWatch log groups the admin Workspace may
// read. Optional: an empty value means the Workspace's log viewer has
// nothing to show, rather than a default that reads whatever a name happens
// to resolve to.
type ObservabilityConfig struct {
	// AWSRegion is the CloudWatch Logs region. Required together with a
	// nonempty LogGroups.
	AWSRegion string `yaml:"awsRegion" json:"awsRegion"`
	// LogGroups is every log group an administrator may read, each under its
	// own operator-chosen display name.
	LogGroups []LogGroupConfig `yaml:"logGroups" json:"logGroups"`
}

// LogGroupConfig binds one operator-chosen display name to one CloudWatch log
// group. Name is not a resource identifier of its own -- it is only how the
// Workspace's log viewer selects among LogGroups -- so an operator is free to
// name any container or service they run alongside AppHub: its own "serve"
// and "worker", a pre-existing shared reverse proxy such as Traefik (see
// compute/aws/routes.go), an external SSO-enforcing auth proxy in front of
// either, or anything else, rather than this repository guessing a naming
// convention (compare: usoss-9's "every identifier is configuration, and none
// has a default"). See docs/design/observability.md.
type LogGroupConfig struct {
	Name     string `yaml:"name" json:"name"`
	LogGroup string `yaml:"logGroup" json:"logGroup"`
}

// StoreConfig selects the state and audit DynamoDB tables; Endpoint is an explicit override.
type StoreConfig struct {
	Region         string `yaml:"region" json:"region"`
	TableName      string `yaml:"tableName" json:"tableName"`
	AuditTableName string `yaml:"auditTableName" json:"auditTableName"`
	Endpoint       string `yaml:"endpoint" json:"endpoint"`
}

// AuthConfig defines trusted providers, exact admin identities and public clients.
// Loaded secrets are excluded from serialization and belong only to the API process.
//
// IDs and secrets may be inline (clientId, transactionKeyFile) or named as
// environment variables (clientIdEnv, transactionKeyEnv). ECS injects the
// latter from Parameter Store through the task definition's secrets block;
// the YAML holds the variable *name*, never the value. Exactly one form is
// required; both is a startup error.
type AuthConfig struct {
	AllowLoopbackHTTP  bool               `yaml:"allowLoopbackHTTP" json:"allowLoopbackHTTP"`
	TransactionKeyFile string             `yaml:"transactionKeyFile" json:"transactionKeyFile"`
	TransactionKeyEnv  string             `yaml:"transactionKeyEnv" json:"transactionKeyEnv"`
	Providers          []ProviderConfig   `yaml:"providers" json:"providers"`
	Admins             []AdminConfig      `yaml:"admins" json:"admins"`
	Clients            []ClientConfig     `yaml:"clients" json:"clients"`
	TransactionKey     credentials.Secret `yaml:"-" json:"-"`
}

// ProviderConfig binds one upstream client to provider-specific admission rules.
// Equal email addresses across providers never establish identity equivalence.
type ProviderConfig struct {
	ID               string             `yaml:"id" json:"id"`
	Label            string             `yaml:"label" json:"label"`
	Kind             string             `yaml:"kind" json:"kind"`
	Issuer           string             `yaml:"issuer" json:"issuer"`
	ClientID         string             `yaml:"clientId" json:"clientId"`
	ClientIDEnv      string             `yaml:"clientIdEnv" json:"clientIdEnv"`
	ClientSecretFile string             `yaml:"clientSecretFile" json:"clientSecretFile"`
	ClientSecretEnv  string             `yaml:"clientSecretEnv" json:"clientSecretEnv"`
	AllowedEmails    []string           `yaml:"allowedEmails" json:"allowedEmails"`
	AllowedDomains   []string           `yaml:"allowedDomains" json:"allowedDomains"`
	ClientSecret     credentials.Secret `yaml:"-" json:"-"`
}

// Admits checks a verified profile against exact normalized addresses/domains.
// It is not authentication: callers must first verify issuer, subject and email.
func (p ProviderConfig) Admits(email string, verified bool) bool {
	if !verified {
		return false
	}
	normalized, domain, ok := normalizeEmail(email)
	if !ok {
		return false
	}
	for _, allowed := range p.AllowedEmails {
		if normalized == allowed {
			return true
		}
	}
	for _, allowed := range p.AllowedDomains {
		if domain == allowed {
			return true
		}
	}
	return false
}

// CallbackURL derives a callback from the fixed public origin only for a configured provider.
func (c Config) CallbackURL(providerID string) (string, bool) {
	for _, p := range c.Auth.Providers {
		if p.ID == providerID {
			return c.PublicOrigin + "/auth/" + p.ID + "/callback", true
		}
	}
	return "", false
}

// AdminConfig grants authority to an exact provider/subject pair, never an email claim.
type AdminConfig struct {
	ProviderID string `yaml:"providerId" json:"providerId"`
	Subject    string `yaml:"subject" json:"subject"`
}

// ClientConfig registers a public OAuth client with exact HTTPS redirect URIs.
type ClientConfig struct {
	ID           string   `yaml:"id" json:"id"`
	RedirectURIs []string `yaml:"redirectUris" json:"redirectUris"`
}

// TargetConfig binds operator-managed AWS infrastructure to deployment policy;
// applications may select its ID but cannot override its infrastructure settings.
type TargetConfig struct {
	Label         string           `yaml:"label" json:"label"`
	AWSConfigFile string           `yaml:"awsConfigFile" json:"awsConfigFile"`
	Deployment    DeploymentConfig `yaml:"deployConfig" json:"deployConfig"`
	Policy        TargetPolicy     `yaml:"policy" json:"policy"`
}

// DeploymentConfig mirrors deploy.Config with stable configuration spelling.
type DeploymentConfig struct {
	ResourcePrefix   string `yaml:"resourcePrefix" json:"resourcePrefix"`
	RouteDomain      string `yaml:"routeDomain" json:"routeDomain"`
	RouteCertificate string `yaml:"routeCertificate" json:"routeCertificate"`
	// InternalRouteDomain and InternalRouteCertificate publish private
	// services on the internal ingress. Both unset leaves private services
	// with no route at all.
	InternalRouteDomain      string          `yaml:"internalRouteDomain" json:"internalRouteDomain"`
	InternalRouteCertificate string          `yaml:"internalRouteCertificate" json:"internalRouteCertificate"`
	AllowedSourceHosts       []string        `yaml:"allowedSourceHosts" json:"allowedSourceHosts"`
	SecretStoreName          string          `yaml:"secretStoreName" json:"secretStoreName"`
	Placement                PlacementConfig `yaml:"placement" json:"placement"`
	WaitTimeout              time.Duration   `yaml:"waitTimeout" json:"waitTimeout"`
	WorkloadIdentityMode     string          `yaml:"workloadIdentityMode" json:"workloadIdentityMode"`
	PostgresRootCertPath     string          `yaml:"postgresRootCertPath" json:"postgresRootCertPath"`
}

// PlacementConfig selects a named operator-managed compute placement.
type PlacementConfig struct {
	Name string `yaml:"name" json:"name"`
}

// DeployConfig translates the target's operator settings into module configuration
// without constructing a provider or sharing its mutable source-host slice.
func (t TargetConfig) DeployConfig() deploy.Config {
	d := t.Deployment
	return deploy.Config{
		ResourcePrefix: d.ResourcePrefix, RouteDomain: d.RouteDomain,
		RouteCertificate:    d.RouteCertificate,
		InternalRouteDomain: d.InternalRouteDomain, InternalRouteCertificate: d.InternalRouteCertificate,
		AllowedSourceHosts: append([]string(nil), d.AllowedSourceHosts...),
		SecretStoreName:    d.SecretStoreName, Placement: compute.Placement{Name: d.Placement.Name},
		WaitTimeout:          d.WaitTimeout,
		WorkloadIdentityMode: d.WorkloadIdentityMode,
		PostgresRootCertPath: d.PostgresRootCertPath,
	}
}

// TargetPolicy bounds user-selected resources, execution modes, relational
// capacity and public exposure.
type TargetPolicy struct {
	ResourceSizes              []ResourceSize         `yaml:"resourceSizes" json:"resourceSizes"`
	MaxReplicas                int                    `yaml:"maxReplicas" json:"maxReplicas"`
	MaxRelationalCapacityUnits float64                `yaml:"maxRelationalCapacityUnits" json:"maxRelationalCapacityUnits"`
	ExecutionModes             []deploy.ExecutionMode `yaml:"executionModes" json:"executionModes"`
	PublicExposure             bool                   `yaml:"publicExposure" json:"publicExposure"`
}

// ResourceSize uses the compute port's units: CPU millicores and memory MiB.
type ResourceSize struct {
	CPU    int `yaml:"cpu" json:"cpu"`
	Memory int `yaml:"memory" json:"memory"`
}

// SourceConfig optionally extra-allowlists exact repositories. Empty means the
// Workspace GitHub App installation is the allowlist; present entries still
// restrict deploys to those URLs and supply per-repository clone auth.
type SourceConfig struct {
	Repositories []RepositoryConfig `yaml:"repositories" json:"repositories"`
}

// RepositoryConfig binds an approved canonical URL to public or GitHub App acquisition.
type RepositoryConfig struct {
	URL       string           `yaml:"url" json:"url"`
	Auth      string           `yaml:"auth" json:"auth"`
	GitHubApp *GitHubAppConfig `yaml:"githubApp" json:"githubApp,omitempty"`
}

// GitHubAppConfig identifies a read-only source installation; its loaded private
// key is worker-only and cannot be serialized with configuration.
//
// AppID/InstallationID and PrivateKeyFile may instead be read from the
// environment (AppIDEnv, InstallationIDEnv, PrivateKeyEnv) so ECS can inject
// them from Parameter Store. Exactly one form of each is required.
type GitHubAppConfig struct {
	AppID             int64              `yaml:"appId" json:"appId"`
	AppIDEnv          string             `yaml:"appIdEnv" json:"appIdEnv"`
	InstallationID    int64              `yaml:"installationId" json:"installationId"`
	InstallationIDEnv string             `yaml:"installationIdEnv" json:"installationIdEnv"`
	PrivateKeyFile    string             `yaml:"privateKeyFile" json:"privateKeyFile"`
	PrivateKeyEnv     string             `yaml:"privateKeyEnv" json:"privateKeyEnv"`
	PrivateKey        credentials.Secret `yaml:"-" json:"-"`
}

// WorkerConfig defines the durable execution limits of the deployment worker.
//
// Build isolation is deliberately not here. A build runs in a task the compute
// provider launches, so what isolates it -- the cluster, the task definitions
// that carry no task role, the subnets and the security groups -- is the
// provider's configuration and lives under `build.task` in the file
// TargetConfig.AWSConfigFile names. This section holds only what the worker
// itself owns: where it checks out source, how many deployments it runs at
// once, and the timings of its own liveness.
type WorkerConfig struct {
	// WorkDir is the worker's private checkout directory. Every build context
	// is created beneath it, and the provider refuses a context outside it.
	WorkDir                  string        `yaml:"workDir" json:"workDir"`
	MaxConcurrentDeployments int           `yaml:"maxConcurrentDeployments" json:"maxConcurrentDeployments"`
	DeploymentTimeout        time.Duration `yaml:"deploymentTimeout" json:"deploymentTimeout"`
	// TeardownTimeout bounds one attempt at deleting an application. Longer
	// than a deployment by default because a managed database alone can take
	// ten minutes or more to delete. A teardown that exceeds it is requeued, up
	// to controlplane.MaxTeardownAttempts attempts.
	TeardownTimeout   time.Duration `yaml:"teardownTimeout" json:"teardownTimeout"`
	HeartbeatInterval time.Duration `yaml:"heartbeatInterval" json:"heartbeatInterval"`
	StaleAfter        time.Duration `yaml:"staleAfter" json:"staleAfter"`
}
