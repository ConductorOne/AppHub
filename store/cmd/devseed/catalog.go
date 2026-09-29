// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// demoDomain names the fictional organization every seeded user, repository
// and route belongs to.
const demoDomain = "acme.example"

// demoOrg is the GitHub organization seeded repositories live under.
const demoOrg = "acme-corp"

type demoUser struct {
	name  string
	email string
}

var demoUsers = []demoUser{
	{"Priya Raman", "priya.raman"},
	{"Marcus Chen", "marcus.chen"},
	{"Sofia Alvarez", "sofia.alvarez"},
	{"Daniel Okafor", "daniel.okafor"},
	{"Hannah Kim", "hannah.kim"},
	{"Liam O'Connor", "liam.oconnor"},
	{"Aisha Patel", "aisha.patel"},
	{"Tom Nakamura", "tom.nakamura"},
	{"Grace Mensah", "grace.mensah"},
	{"Ethan Brooks", "ethan.brooks"},
	{"Maya Goldberg", "maya.goldberg"},
	{"Carlos Diaz", "carlos.diaz"},
	{"Nina Petrov", "nina.petrov"},
	{"Jordan Lee", "jordan.lee"},
}

// scenario is how an application's most recent deployment ended.
type scenario int

const (
	running      scenario = iota
	failedLatest          // latest deploy failed; an earlier one still serves
	deploying             // a deploy is in progress
	interrupted           // the worker stopped mid-deploy
	draft                 // created, never deployed
	neverRan              // every deploy so far has failed
)

type database int

const (
	noDatabase database = iota
	postgres
	dynamo
)

type demoApp struct {
	name       string
	category   string
	repo       string
	schedule   string // cron expression; empty means a long-running service
	public     bool
	mcp        bool
	db         database
	extensions []string
	bucket     bool
	secrets    []string
	scenario   scenario
}

var demoApps = []demoApp{
	// Customer-facing
	{name: "Storefront", category: "customer-facing", repo: "storefront", public: true, db: postgres, bucket: true, secrets: []string{"STRIPE_SECRET_KEY", "SENDGRID_API_KEY"}},
	{name: "Customer Portal", category: "customer-facing", repo: "customer-portal", public: true, db: postgres, secrets: []string{"AUTH0_CLIENT_SECRET"}},
	{name: "Status Page", category: "customer-facing", repo: "status-page", public: true},
	{name: "Checkout API", category: "customer-facing", repo: "checkout-api", public: true, db: postgres, extensions: []string{"pgcrypto", "uuid-ossp"}, secrets: []string{"STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"}},
	{name: "Partner API", category: "customer-facing", repo: "partner-api", public: true, db: dynamo, secrets: []string{"PARTNER_HMAC_KEY"}, scenario: failedLatest},
	{name: "Referral Service", category: "customer-facing", repo: "referral-service", public: true, db: dynamo},
	{name: "Help Center", category: "customer-facing", repo: "help-center", public: true, db: postgres, extensions: []string{"pg_trgm", "unaccent"}},

	// Internal tools
	{name: "Expense Tracker", category: "internal-tools", repo: "expense-tracker", db: postgres, bucket: true, secrets: []string{"RAMP_API_TOKEN"}},
	{name: "Onboarding Hub", category: "internal-tools", repo: "onboarding-hub", db: postgres, secrets: []string{"SLACK_BOT_TOKEN"}},
	{name: "Office Booking", category: "internal-tools", repo: "office-booking", db: dynamo},
	{name: "Vendor Directory", category: "internal-tools", repo: "vendor-directory", db: postgres, extensions: []string{"citext"}},
	{name: "Sales Commission Calculator", category: "internal-tools", repo: "commission-calc", db: postgres, secrets: []string{"SALESFORCE_CLIENT_SECRET"}, scenario: deploying},
	{name: "Headcount Planner", category: "internal-tools", repo: "headcount-planner", scenario: draft},
	{name: "Swag Store", category: "internal-tools", repo: "swag-store", db: dynamo, bucket: true},
	{name: "Contract Tracker", category: "internal-tools", repo: "contract-tracker", db: postgres, bucket: true, secrets: []string{"DOCUSIGN_INTEGRATION_KEY"}},

	// Data and jobs
	{name: "Nightly Billing Export", category: "data-jobs", repo: "billing-export", schedule: "0 2 * * *", db: postgres, bucket: true, secrets: []string{"SNOWFLAKE_PASSWORD"}},
	{name: "CRM Sync", category: "data-jobs", repo: "crm-sync", schedule: "*/15 * * * *", db: dynamo, secrets: []string{"HUBSPOT_TOKEN"}},
	{name: "Invoice Reconciler", category: "data-jobs", repo: "invoice-reconciler", schedule: "0 6 * * 1-5", db: postgres},
	{name: "Usage Rollup", category: "data-jobs", repo: "usage-rollup", schedule: "0 * * * *", db: dynamo, bucket: true},
	{name: "Churn Score Pipeline", category: "data-jobs", repo: "churn-score", schedule: "30 3 * * *", db: postgres, extensions: []string{"vector"}, scenario: failedLatest},
	{name: "Data Retention Sweeper", category: "data-jobs", repo: "retention-sweeper", schedule: "0 4 * * 0", bucket: true},
	{name: "Event Ingest Worker", category: "data-jobs", repo: "event-ingest", db: dynamo, secrets: []string{"KAFKA_SASL_PASSWORD"}},

	// Developer tools
	{name: "Release Notes Bot", category: "developer-tools", repo: "release-notes-bot", secrets: []string{"GITHUB_TOKEN", "SLACK_WEBHOOK_URL"}},
	{name: "Flaky Test Tracker", category: "developer-tools", repo: "flaky-tests", db: postgres, secrets: []string{"BUILDKITE_API_TOKEN"}},
	{name: "Preview Env Janitor", category: "developer-tools", repo: "preview-janitor", schedule: "0 */6 * * *", secrets: []string{"GITHUB_TOKEN"}},
	{name: "Dependency Dashboard", category: "developer-tools", repo: "dependency-dashboard"},
	{name: "Feature Flag Service", category: "developer-tools", repo: "flagd", db: dynamo},
	{name: "PR Review Router", category: "developer-tools", repo: "review-router", db: dynamo, secrets: []string{"GITHUB_APP_PRIVATE_KEY"}, scenario: interrupted},

	// AI and agents
	{name: "Support Copilot", category: "ai-agents", repo: "support-copilot", public: true, mcp: true, db: postgres, extensions: []string{"vector"}, secrets: []string{"ANTHROPIC_API_KEY", "ZENDESK_API_TOKEN"}},
	{name: "Knowledge Base MCP", category: "ai-agents", repo: "kb-mcp", public: true, mcp: true, db: postgres, extensions: []string{"vector", "pg_trgm"}, secrets: []string{"ANTHROPIC_API_KEY"}},
	{name: "Meeting Summarizer", category: "ai-agents", repo: "meeting-summarizer", db: dynamo, bucket: true, secrets: []string{"ANTHROPIC_API_KEY", "GONG_ACCESS_KEY"}},
	{name: "Sales Research Agent", category: "ai-agents", repo: "sales-research-agent", db: postgres, extensions: []string{"vector"}, secrets: []string{"ANTHROPIC_API_KEY", "APOLLO_API_KEY"}},
	{name: "Incident Triage Agent", category: "ai-agents", repo: "incident-triage", db: dynamo, secrets: []string{"ANTHROPIC_API_KEY", "PAGERDUTY_TOKEN"}},
	{name: "Docs Q&A Bot", category: "ai-agents", repo: "docs-qa-bot", secrets: []string{"ANTHROPIC_API_KEY"}, scenario: draft},
	{name: "Contract Review Assistant", category: "ai-agents", repo: "contract-review", db: postgres, extensions: []string{"vector"}, bucket: true, secrets: []string{"ANTHROPIC_API_KEY"}, scenario: neverRan},

	// Security and compliance
	{name: "Access Review Portal", category: "security", repo: "access-reviews", db: postgres, secrets: []string{"OKTA_CLIENT_SECRET"}},
	{name: "Secret Scanner", category: "security", repo: "secret-scanner", schedule: "0 */4 * * *", secrets: []string{"GITHUB_TOKEN"}},
	{name: "Phishing Report Inbox", category: "security", repo: "phish-inbox", db: dynamo, secrets: []string{"GMAIL_SERVICE_ACCOUNT"}},
	{name: "Vendor Risk Tracker", category: "security", repo: "vendor-risk", db: postgres},
	{name: "Audit Evidence Collector", category: "security", repo: "evidence-collector", schedule: "0 5 * * *", db: postgres, bucket: true, secrets: []string{"VANTA_API_TOKEN"}},

	// Monitoring and ops
	{name: "On-call Dashboard", category: "observability", repo: "oncall-dashboard", secrets: []string{"PAGERDUTY_TOKEN"}},
	{name: "Cost Explorer", category: "observability", repo: "cost-explorer", db: postgres, secrets: []string{"DATADOG_API_KEY"}},
	{name: "Uptime Prober", category: "observability", repo: "uptime-prober", schedule: "*/5 * * * *", db: dynamo},
	{name: "SLO Tracker", category: "observability", repo: "slo-tracker", db: dynamo},

	// Docs and content
	{name: "Engineering Handbook", category: "docs", repo: "handbook"},
	{name: "Marketing Site", category: "docs", repo: "marketing-site", public: true, bucket: true},
	{name: "API Reference", category: "docs", repo: "api-reference", public: true},
}
