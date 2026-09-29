// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials/workload"
	"github.com/conductorone/apphub/modules"
)

// ModuleID is the identifier this module is registered and invoked under.
//
// It is stable across releases because it is persisted on request rows and used
// as a queue job type in the system this was ported from, so changing it
// orphans stored work. It is deliberately not "deploy-ecs", which is what the
// source called it: the name of a cloud service is the wrong name for a module
// whose whole claim is that it does not know which one is underneath.
const ModuleID = "deploy-container"

// The environment variables a deployed workload receives for the resources this
// module provisions for it.
//
// These are a contract with the application, not with a substrate, so they are
// constants rather than configuration: an application built against this
// platform reads DATABASE_HOST wherever it is deployed. The password arrives as
// a secret binding under the same name, resolved by the runtime at launch, and
// is the one value here this module never puts in an environment variable.
const (
	EnvDatabaseHost     = "DATABASE_HOST"
	EnvDatabasePort     = "DATABASE_PORT"
	EnvDatabaseName     = "DATABASE_NAME"
	EnvDatabaseUser     = "DATABASE_USER"
	EnvDatabasePassword = "DATABASE_PASSWORD"
	EnvTableName        = "TABLE_NAME"
	EnvBucketName       = "BUCKET_NAME"
	EnvBucketURI        = "BUCKET_URI"
)

// ExtensionInstaller runs admin SQL after the relational endpoint is ready.
// The deployment module owns the lifecycle, not the database driver.
type ExtensionInstaller func(context.Context, compute.SQLEndpoint, string, compute.SecretValue, string, []string) error

// Module deploys an application onto a compute provider.
//
// Every dependency arrives through [New] and none is settable afterwards, which
// is this repository's convention and the reason a registered module is always
// a wired module. The source used late-bound Set* methods on four of its nine
// modules, so a module could be registered, invoked, and only then discover it
// had no repository.
type Module struct {
	modules.BaseModule

	provider          compute.Provider
	store             Store
	fetcher           SourceFetcher
	attestations      AttestationProvisioner
	cfg               Config
	installExtensions ExtensionInstaller
}

var _ modules.Module = (*Module)(nil)

// New builds the module, or refuses to.
//
// It refuses on a nil dependency and on a configuration it cannot use, both
// wrapped in [github.com/conductorone/apphub/modules.ErrNotConfigured] so a caller
// can tell an operator's problem from a requester's without knowing which
// module or which dependency.
func New(provider compute.Provider, store Store, fetcher SourceFetcher, attestations AttestationProvisioner, cfg Config, installer ...ExtensionInstaller) (*Module, error) {
	if provider == nil {
		return nil, modules.Missing(ModuleID, "compute provider")
	}
	if store == nil {
		return nil, modules.Missing(ModuleID, "application store")
	}
	if fetcher == nil {
		return nil, modules.Missing(ModuleID, "application source fetcher")
	}
	if attestations == nil && cfg.WorkloadIdentityMode != "native" {
		return nil, modules.Missing(ModuleID, "workload attestation provisioner")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", modules.ErrNotConfigured, err)
	}
	if len(installer) > 1 || (len(installer) == 1 && installer[0] == nil) {
		return nil, modules.Missing(ModuleID, "PostgreSQL extension installer")
	}
	m := &Module{
		BaseModule: modules.NewBaseModule(
			ModuleID,
			"Deploy application",
			"Build an application from its source and run it on the configured compute provider",
			"rocket_launch",
			"Deployments",
		),
		provider: provider, store: store, fetcher: fetcher,
		attestations: attestations, cfg: cfg,
	}
	if len(installer) == 1 {
		m.installExtensions = installer[0]
	}
	return m, nil
}

// Schema implements [github.com/conductorone/apphub/modules.Module].
//
// One parameter, which is a deliberate reduction. The source declared six and
// read four more that it did not declare — databaseType, bucketType, bucketName
// and bucketAZ, all set server-side from the application row -- its own comment
// on Validate (container.go:1052-1058) says so. Everything a deploy needs beyond "which application" is
// on the application record, so making the record the single source removes the
// undeclared-parameter class entirely rather than checking for it.
func (m *Module) Schema() *modules.JSONSchema {
	return &modules.JSONSchema{
		Type: "object",
		Properties: map[string]modules.JSONSchemaProperty{
			"applicationId": {
				Type:        "string",
				Description: "The application to deploy. Everything else is read from its record.",
			},
		},
		Required: []string{"applicationId"},
	}
}

// Validate implements [github.com/conductorone/apphub/modules.Module].
func (m *Module) Validate(params map[string]any) error {
	if err := modules.ValidateDeclaredParams(m.Schema(), params); err != nil {
		return err
	}
	id, ok := params["applicationId"].(string)
	if !ok || strings.TrimSpace(id) == "" {
		return errors.New("applicationId is required and must be a non-empty string")
	}
	return nil
}

// Execute implements [github.com/conductorone/apphub/modules.Module].
//
// The two return values are independent, and this module is one of the reasons
// that is written into the interface: a deploy that created a bucket, a
// database and an identity and then failed to start the workload returns both
// an error and a Result carrying what it made, because that state exists and a
// caller needs it in order to clean up or resume.
func (m *Module) Execute(ctx context.Context, _ string, params map[string]any) (*modules.Result, error) {
	if err := m.Validate(params); err != nil {
		return nil, err
	}
	appID, _ := params["applicationId"].(string)

	app, err := m.store.GetApplication(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("loading application %q: %w", appID, err)
	}
	if app == nil {
		return nil, fmt.Errorf("%w: the store returned no application and no error for %q",
			ErrInvalidApplication, appID)
	}

	// Everything that can be decided without touching a provider is decided
	// first, and a refusal here changes nothing: the application is not marked
	// deploying, no resource is created, and the record is exactly as it was.
	// The source marked the application "deploying" in its second statement
	// (container.go:89-90) and left it there on every subsequent refusal.
	plan, err := newPlan(m.cfg, app, m.provider.Name())
	if err != nil {
		return nil, err
	}
	if len(app.Database.Extensions) > 0 && m.installExtensions == nil {
		return nil, fmt.Errorf("%w: this worker has no PostgreSQL extension installer", ErrNotConfigured)
	}
	if err := plan.checkCapabilities(m.provider.Capabilities()); err != nil {
		return nil, err
	}
	// Everything the provider can be ASKED without being told to do anything.
	// A binding to a secret that has been deleted, or that lives somewhere the
	// workload cannot reach it, is a record that cannot deploy — and finding
	// that out from EnsureService means the image, the identity and the
	// database already exist.
	if step, err := m.preflightSecrets(ctx, plan, app); err != nil {
		return nil, fmt.Errorf("%s: %w", step, err)
	}

	modules.ReportProgress(ctx, 2, "Starting deployment")
	app.Status = StatusDeploying
	app.FailedStep = ""
	app.FailureClass = ""
	if m.cfg.WorkloadIdentityMode == "native" {
		app.Artifacts.AttestationRevision = 0
	}
	if err := m.checkpoint(ctx, app, "starting"); err != nil {
		err = errors.Join(err, m.recordFailure(ctx, app, "starting", err))
		return m.result(app, false, "could not record deployment start"), err
	}

	step, runErr := m.run(ctx, plan, app)
	if runErr != nil {
		runErr = errors.Join(runErr, m.recordFailure(ctx, app, step, runErr))
		// Both, and in that order of importance. The Result is what exists.
		return m.result(app, false, fmt.Sprintf("deploy failed at %s", step)), runErr
	}

	app.Status = StatusRunning
	app.FailedStep = ""
	app.FailureClass = ""
	lastSuccess := app.LastDeployedAt
	app.LastDeployedAt = time.Now().UTC()
	if err := m.checkpoint(ctx, app, "complete"); err != nil {
		// Cloud effects exist, but durable finalization failed. Keep the last
		// successful timestamp and preserve the finalization and failure-save errors.
		app.LastDeployedAt = lastSuccess
		err = errors.Join(err, m.recordFailure(ctx, app, "complete", err))
		return m.result(app, false, "deployed, but the application record could not be updated"), err
	}
	message := "deployed"
	if app.Execution == ExecutionScheduled {
		message = "schedule installed"
	}
	modules.ReportProgress(ctx, 100, message)
	return m.result(app, true, message), nil
}

// result renders what the deploy created.
//
// Only references and non-secret names. A [compute.Ref] names a resource and a
// bucket URI is a location; neither is material, and nothing that is material
// reaches this map.
func (m *Module) result(app *Application, ok bool, message string) *modules.Result {
	data := map[string]any{
		"applicationId": app.ID,
		"provider":      m.provider.Name(),
		"step":          app.DeployStep,
	}
	for key, ref := range map[string]compute.Ref{
		"identity":     app.Artifacts.Identity,
		"repository":   app.Artifacts.Repository,
		"workload":     app.Artifacts.Workload,
		"bucket":       app.Artifacts.Bucket,
		"relational":   app.Artifacts.Relational,
		"keyValueName": app.Artifacts.KeyValue,
	} {
		if !ref.IsZero() {
			data[key] = ref.String()
		}
	}
	if app.Artifacts.Image != "" {
		data["image"] = string(app.Artifacts.Image)
	}
	if len(app.Artifacts.Secrets) > 0 {
		refs := make(map[string]string, len(app.Artifacts.Secrets))
		for name, ref := range app.Artifacts.Secrets {
			refs[name] = ref.String()
		}
		data["secrets"] = refs
	}
	if len(app.Artifacts.Addresses) > 0 {
		data["addresses"] = append([]string(nil), app.Artifacts.Addresses...)
	}
	return &modules.Result{Success: ok, Message: message, Data: data}
}

// recordFailure persists which step failed and what class of failure it was.
//
// It deliberately does not persist the provider's error text, which is what the
// source did (container.go:999, storing err.Error() on the application row).
// A provider is free to put anything in an error string — the fake has a
// deliberate defect that interpolates an admin password into one — and an
// application record is read by a UI, exported, and kept. So what is stored is
// the step, which this module names, and a classification derived by asking the
// error which of the compute taxonomy's sentinels it is, which is a closed set
// this module also names. The full error still reaches the caller as Execute's
// return value; it just does not become a durable artifact.
func (m *Module) recordFailure(ctx context.Context, app *Application, step string, err error) error {
	app.Status = StatusFailed
	app.FailedStep = step
	app.FailureClass = classify(err)
	// A canceled build must not cancel the durable failure record. Preserve
	// both errors when storage also fails; neither replaces the other.
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return m.checkpoint(saveCtx, app, step)
}

// checkpoint fences subsequent effects on durable intent and captured artifacts.
// Names are module-authored phases only; provider errors never enter the record.
func (m *Module) checkpoint(ctx context.Context, app *Application, step string) error {
	app.DeployStep = step
	if err := m.store.SaveApplication(ctx, app); err != nil {
		return fmt.Errorf("persisting deployment checkpoint %s: %w", step, err)
	}
	return nil
}

// failureClasses is the closed set of classifications recordFailure may store,
// in the order they are tried.
//
// Ordered because the sentinels are not mutually exclusive under errors.Is: a
// module-level refusal built with modules.Missing also matches nothing else,
// but a provider error can wrap two. The first match wins and the order is
// most-specific-first, so a reader gets the actionable one.
var failureClasses = []struct {
	sentinel error
	class    string
}{
	{ErrSourceRefused, "source-refused"},
	{ErrInvalidApplication, "invalid-application"},
	{ErrNotConfigured, "not-configured"},
	{compute.ErrNotPermitted, "not-permitted"},
	{compute.ErrUnsupported, "unsupported"},
	{compute.ErrNotOwned, "not-owned"},
	{compute.ErrInvalidSpec, "invalid-spec"},
	{compute.ErrForeignRef, "foreign-reference"},
	{compute.ErrNotFound, "not-found"},
	{compute.ErrTimeout, "timeout"},
	{compute.ErrFailed, "resource-failed"},
	{compute.ErrTransient, "transient"},
}

// classify names the failure class, or reports that there is not one.
//
// "unclassified" is a real answer rather than a shrug: it says the failure was
// not one of the classes this module knows how to describe, which is what an
// operator needs to know before going to the logs. It is never a substitute for
// the error, which the caller has.
func classify(err error) string {
	for _, c := range failureClasses {
		if errors.Is(err, c.sentinel) {
			return c.class
		}
	}
	return "unclassified"
}

// preflightSecrets asks the provider everything it can be asked about the
// secret references this deploy will bind, before anything is created and
// before the record is written.
//
// # Why this is a separate pass rather than a check inside the plan
//
// [newPlan] establishes what a Ref says: it is non-zero, it names a secret, it
// was issued by this provider, and no two bindings claim one variable. It
// cannot establish what is TRUE of it. A reference can be perfectly well formed
// and name a secret somebody deleted, or one that lives in a placement the
// workload cannot reach — both ordinary operator transitions, and both refused
// by the provider only when the workload is created, which is after the image,
// the identity and the database exist.
//
// [github.com/conductorone/apphub/compute.SecretStore.Describe] is the operation
// that makes the question answerable without reading material. It returns a
// locator and a location; this module compares them and never asks for a value.
//
// # Which references it covers, and why that is more than the plan's
//
// Both sets that become a [compute.SecretBinding] later in this deploy, which
// is not only the application's declared bindings:
//
//   - [Plan.Secrets], the bindings the application asked for; and
//   - the references on [Artifacts.Secrets], which this module issued for
//     itself on an earlier deploy and adopts into the binder before it does
//     anything (see [Module.provisionData]). The administrative password of a
//     relational database is one of these, and it is bound to
//     [EnvDatabasePassword] by [Module.workloadInputs].
//
// Covering only the first left the one binding this module issues for itself as
// the one binding nothing asked about, and it fails in exactly the two ways
// above: a deleted secret surfaces from the read-back in [Module.adminPassword]
// at the relational step, and a changed [Config.Placement] surfaces from
// EnsureService — with the image, the identity and a new database already in
// existence, which is the outcome this pass is here to prevent. On a first
// deploy the set is empty, so nothing changes there.
//
// # The placement comparison, and the two answers to it
//
// Whether placement constrains a binding is the store's answer, not this
// module's guess. A store that keys secrets by placement reports
// [compute.SecretPlacementScoped] and where the secret is; one whose secrets are
// account-global reports [compute.SecretPlacementGlobal] and nowhere.
//
// For a scoped store there is something to compare, and comparing needs a name:
// an unnamed [Config.Placement] means "whatever the provider's default is",
// which the provider knows and this module does not. So a scoped store plus an
// unnamed placement is refused, here, before anything exists — and for a global
// store no placement is required at all, because there is nothing it would be
// compared against.
//
// That distinction is not tidiness. Requiring a placement unconditionally would
// have imposed a configuration on AWS deployments to satisfy a check that can
// never fire on them.
func (m *Module) preflightSecrets(ctx context.Context, plan *Plan, app *Application) (string, error) {
	subjects := preflightSubjects(plan, app)
	if len(subjects) == 0 {
		return "", nil
	}
	store, err := m.provider.Secrets()
	if err != nil {
		return "secret-store", err
	}
	want := m.cfg.Placement.Name
	for _, s := range subjects {
		info, err := store.Describe(ctx, s.secret)
		if err != nil {
			return "secret-preflight", fmt.Errorf("%s references %s, "+
				"which this deploy cannot bind: %w", s.what, s.secret, err)
		}
		if info == nil {
			return "secret-preflight", fmt.Errorf("%w: provider %q described secret %s as "+
				"nothing and reported no error", compute.ErrFailed, m.provider.Name(), s.secret)
		}
		switch info.PlacementScope {
		case compute.SecretPlacementGlobal:
			// Nothing to compare: every workload this provider runs can bind it.
			continue
		case compute.SecretPlacementScoped:
		default:
			// An answer this module cannot interpret is fatal, not ignored. A
			// provider that reported no scope would otherwise have its
			// placement silently unchecked, which is the one outcome the
			// preflight exists to prevent.
			return "secret-preflight", fmt.Errorf("%w: provider %q reported placement scope %q "+
				"for secret %s, which is not one this interface defines, so whether the binding "+
				"is placed correctly cannot be established", compute.ErrFailed,
				m.provider.Name(), info.PlacementScope, s.secret)
		}
		if want == "" {
			return "secret-preflight", fmt.Errorf("%w: provider %q places secrets, so a binding "+
				"is only valid in the workload's own placement — and Placement is not "+
				"configured. This module cannot check that against a default only the provider "+
				"can name; set Placement so the check can happen before anything is created",
				ErrNotConfigured, m.provider.Name())
		}
		if info.Placement.Name != want {
			return "secret-preflight", fmt.Errorf("%w: %s references a "+
				"secret in placement %q, and this application is deployed to %q; a workload can "+
				"only bind a secret in its own placement, and a provider must not copy material "+
				"between them", ErrInvalidApplication, s.what, info.Placement.Name, want)
		}
	}
	return "", nil
}

// preflightSubject is one reference [Module.preflightSecrets] asks about, and
// the phrase a refusal names it by.
//
// The phrase differs between the two sets because what identifies a reference
// to an operator differs: an application's binding is a position in a list it
// wrote and the variable it chose, while a reference this module holds on the
// record has a logical name and no position. Neither phrase carries material —
// a secret's name is already in the record, the workload's environment and the
// provider's own listings.
type preflightSubject struct {
	what   string
	secret compute.Ref
}

// preflightSubjects is every reference this deploy will turn into a
// [compute.SecretBinding], in a fixed order.
//
// Fixed because a map has none and a refusal that names a different binding on
// each run of the same broken record is a refusal an operator cannot act on:
// the recorded references are walked in sorted order rather than the map's.
func preflightSubjects(plan *Plan, app *Application) []preflightSubject {
	subjects := make([]preflightSubject, 0, len(plan.Secrets)+len(app.Artifacts.Secrets))
	for i, b := range plan.Secrets {
		subjects = append(subjects, preflightSubject{
			what:   fmt.Sprintf("secret binding %d for %q", i, b.EnvName),
			secret: b.Secret,
		})
	}
	names := make([]string, 0, len(app.Artifacts.Secrets))
	for name := range app.Artifacts.Secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ref := app.Artifacts.Secrets[name]
		if ref.IsZero() {
			// The binder ignores a zero reference on adopt, so nothing will
			// bind it and there is nothing to ask about.
			continue
		}
		subjects = append(subjects, preflightSubject{
			what:   fmt.Sprintf("the secret %q this application already holds", name),
			secret: ref,
		})
	}
	return subjects
}

// runState is what a deploy learns while it runs: values that belong to this
// execution and not to the application record.
//
// It is a separate type rather than fields on [Application] because an
// application record is persisted, and a persisted field that is only
// meaningful during one deploy is a field that is stale the rest of the time.
type runState struct {
	identity   compute.Ref
	endpoint   compute.SQLEndpoint
	tableName  string
	bucketName string
	bucketURI  string
	// materialsEnv is what the credential layer asked to be set verbatim.
	materialsEnv map[string]string
	binder       *secretBinder
	// adminPassword is the database's administrative password for this run. It
	// is held only for the second EnsureRelational that attaches the workload
	// ingress; a provider must not rotate on a re-Ensure, so the same value has
	// to go in.
	adminPassword compute.SecretValue
}

// run walks the plan. It returns the step it was on when it stopped, so a
// failure names a phase rather than a line number, and it records every
// artifact onto app as it is created — including on the failure path, because a
// resource that exists is a resource somebody has to know about.
func (m *Module) run(ctx context.Context, plan *Plan, app *Application) (string, error) {
	st := &runState{}

	// Identity first: everything else either grants to it or references it, and
	// creating it costs nothing if the deploy stops later.
	modules.ReportProgress(ctx, 5, "Ensuring workload identity")
	if err := m.checkpoint(ctx, app, "workload-identity"); err != nil {
		return "workload-identity", err
	}
	identity, err := m.provider.Identities().EnsureWorkloadIdentity(ctx, plan.Identity)
	if identity != nil {
		app.Artifacts.Identity = identity.Ref
		app.Artifacts.Attestation = attestation(identity)
		st.identity = identity.Ref
		err = errors.Join(err, m.checkpoint(ctx, app, "workload-identity"))
	}
	if err != nil {
		return "workload-identity", err
	}

	if step, err := m.imageFor(ctx, plan, app); err != nil {
		return step, err
	}
	if step, err := m.provisionData(ctx, plan, app, st); err != nil {
		return step, err
	}
	bindings, step, err := m.workloadInputs(ctx, plan, app, st)
	if err != nil {
		return step, err
	}
	if step, err := m.startWorkload(ctx, plan, app, st, resolved{
		image:    app.Artifacts.Image,
		identity: st.identity,
		env:      dataEnv(plan, app, st),
		secrets:  bindings,
	}); err != nil {
		return step, err
	}
	return m.openDatabaseToTheWorkload(ctx, plan, app, st)
}

// openDatabaseToTheWorkload re-Ensures the database with an ingress rule naming
// the workload, which is the first moment there is a workload to name.
//
// It is a second call rather than an argument to the first because the two
// resources depend on each other in opposite directions: the workload needs the
// database's endpoint in its environment, and the database's only permitted
// peer is the workload. Splitting it resolves that without either resource
// existing in a state somebody else can reach — between the two calls the
// database accepts no inbound connections at all.
func (m *Module) openDatabaseToTheWorkload(ctx context.Context, plan *Plan, app *Application, st *runState) (string, error) {
	if plan.Relational == nil {
		return "", nil
	}
	ingress, err := plan.RelationalIngress(app.Artifacts.Workload)
	if err != nil {
		return "database-ingress", err
	}
	provisioner, err := m.provider.Relational()
	if err != nil {
		return "database-ingress", err
	}
	spec := *plan.Relational
	spec.Ingress = ingress
	// The same password the database already has. A provider must not rotate on
	// a re-Ensure, and passing a different one would be asking it to.
	spec.AdminPassword = st.adminPassword
	modules.ReportProgress(ctx, 95, "Opening the database to the workload")
	if err := m.checkpoint(ctx, app, "database-ingress"); err != nil {
		return "database-ingress", err
	}
	status, err := provisioner.EnsureRelational(ctx, spec)
	if status != nil {
		app.Artifacts.Relational = status.Ref
	}
	return "database-ingress", errors.Join(err, m.checkpoint(ctx, app, "database-ingress"))
}

// imageFor builds the image, or reuses a pinned one without touching the
// source or the registry.
func (m *Module) imageFor(ctx context.Context, plan *Plan, app *Application) (string, error) {
	if app.PinnedImage == "" {
		return m.buildImage(ctx, plan, app)
	}
	if app.Artifacts.Repository.IsZero() {
		return "image-build", fmt.Errorf("%w: a pinned image needs the repository an earlier deploy "+
			"created, and this application has none recorded", ErrInvalidApplication)
	}
	app.Artifacts.Image = app.PinnedImage
	modules.ReportProgress(ctx, 55, "Reusing the last successful image")
	return "", nil
}

// buildImage ensures the repository, fetches the source and builds. On success
// it records the image on the application and returns an empty step.
func (m *Module) buildImage(ctx context.Context, plan *Plan, app *Application) (string, error) {
	registry, err := m.provider.Registry()
	if err != nil {
		return "image-registry", err
	}
	builder, err := m.provider.Builder()
	if err != nil {
		return "image-build", err
	}

	modules.ReportProgress(ctx, 10, "Ensuring image repository")
	if err := m.checkpoint(ctx, app, "image-repository"); err != nil {
		return "image-repository", err
	}
	repo, err := registry.EnsureRepository(ctx, plan.Repository)
	if repo != nil {
		app.Artifacts.Repository = repo.Ref
		err = errors.Join(err, m.checkpoint(ctx, app, "image-repository"))
	}
	if err != nil {
		return "image-repository", err
	}

	modules.ReportProgress(ctx, 15, "Fetching application source")
	if err := m.checkpoint(ctx, app, "source-fetch"); err != nil {
		return "source-fetch", err
	}
	dir, err := m.fetcher.Fetch(ctx, plan.Source)
	if err != nil {
		return "source-fetch", err
	}
	if strings.TrimSpace(dir) == "" {
		return "source-fetch", fmt.Errorf("%w: the source fetcher reported success and returned "+
			"no directory", ErrInvalidApplication)
	}

	tag, err := deployTag()
	if err != nil {
		return "image-build", err
	}
	// An immutable per-deploy tag, and a moving one for humans. The workload
	// runs whichever of the two is immutable — see below.
	perDeploy := compute.ImageRef(repo.Prefix + ":" + tag)

	modules.ReportProgress(ctx, 20, "Building and pushing the image")
	if err := m.checkpoint(ctx, app, "image-build"); err != nil {
		return "image-build", err
	}
	built, err := builder.Build(ctx, plan.Build(dir,
		[]compute.ImageRef{perDeploy, compute.ImageRef(repo.Prefix + ":latest")}))
	// Prefer the digest. It is the only reference that cannot be repointed at
	// different content between this call and the workload starting, and the
	// source system ran its workloads off a tag that a concurrent deploy of the
	// same application would overwrite. A builder that reports no digest is
	// explicitly allowed by the interface, so the per-deploy tag is the
	// fallback — never ":latest", which every deploy moves.
	// A partial build result can include images already pushed even on error.
	if built != nil && len(built.Images) > 0 {
		app.Artifacts.Image = perDeploy
		if built.Digest != "" {
			app.Artifacts.Image = compute.ImageRef(repo.Prefix + "@" + built.Digest)
		}
		err = errors.Join(err, m.checkpoint(ctx, app, "image-build"))
	}
	if err != nil {
		return "image-build", err
	}
	if built == nil || len(built.Images) == 0 {
		return "image-build", fmt.Errorf("%w: the builder reported success and pushed nothing",
			compute.ErrInvalidSpec)
	}

	modules.ReportProgress(ctx, 55, "Image pushed")
	return "", nil
}

// provisionData creates the database and the bucket, grants the workload
// identity access to each, and leaves a binder on the run state holding every
// secret reference this deploy knows about.
func (m *Module) provisionData(ctx context.Context, plan *Plan, app *Application, st *runState) (string, error) {
	var store compute.SecretStore
	if m.provider.Capabilities().Has(compute.CapSecretStore) {
		var err error
		store, err = m.provider.Secrets()
		if err != nil {
			return "secret-store", err
		}
	}
	st.binder = newSecretBinder(m.provider.Name(), store, m.cfg, app.ID)
	for name, ref := range app.Artifacts.Secrets {
		st.binder.adopt(name, ref)
	}

	if plan.Relational != nil {
		if err := m.provisionRelational(ctx, plan, app, st); err != nil {
			app.Artifacts.Secrets = st.binder.refs()
			return "relational-database", err
		}
		if len(app.Database.Extensions) > 0 {
			if err := m.provisionExtensions(ctx, plan, app, st); err != nil {
				app.Artifacts.Secrets = st.binder.refs()
				return "database-extensions", err
			}
		}
	}
	if plan.KeyValue != nil {
		if err := m.provisionKeyValue(ctx, plan, app, st); err != nil {
			app.Artifacts.Secrets = st.binder.refs()
			return "key-value-table", err
		}
	}
	if plan.Bucket != nil {
		if err := m.provisionBucket(ctx, plan, app, st); err != nil {
			app.Artifacts.Secrets = st.binder.refs()
			return "object-store", err
		}
	}
	app.Artifacts.Secrets = st.binder.refs()
	if err := m.checkpoint(ctx, app, "environment-secrets"); err != nil {
		return "environment-secrets", err
	}
	if err := m.reconcileEnvSecrets(ctx, app, st.binder); err != nil {
		return "environment-secrets", err
	}
	return "", nil
}

// provisionRelational creates the database, storing its administrative password
// before the database exists and never rotating it afterwards.
func (m *Module) provisionRelational(ctx context.Context, plan *Plan, app *Application, st *runState) error {
	provisioner, err := m.provider.Relational()
	if err != nil {
		return err
	}
	modules.ReportProgress(ctx, 60, "Provisioning the database")

	password, err := m.adminPassword(ctx, app, st.binder)
	if err != nil {
		return err
	}
	st.adminPassword = password
	spec := *plan.Relational
	spec.AdminPassword = password

	if err := m.checkpoint(ctx, app, "relational-database"); err != nil {
		return err
	}
	status, err := provisioner.EnsureRelational(ctx, spec)
	if status != nil {
		app.Artifacts.Relational = status.Ref
		err = errors.Join(err, m.checkpoint(ctx, app, "relational-database"))
	}
	if err != nil {
		return err
	}
	if status.Phase != compute.PhaseReady {
		status, err = provisioner.WaitForRelational(ctx, status.Ref, compute.WaitOptions{
			Timeout: m.cfg.waitTimeout(),
		})
		if err != nil {
			return err
		}
	}
	st.endpoint = status.Endpoint
	return nil
}

// provisionExtensions grants the worker temporary access to the database for
// admin SQL. The final ingress is still workload-only; remove the worker rule
// on both success and failure. A failed cleanup fails the deploy rather than
// reporting success while the admin endpoint remains reachable.
func (m *Module) provisionExtensions(ctx context.Context, plan *Plan, app *Application, st *runState) (result error) {
	if m.installExtensions == nil {
		return fmt.Errorf("%w: this worker has no PostgreSQL extension installer", ErrNotConfigured)
	}
	provisioner, err := m.provider.Relational()
	if err != nil {
		return err
	}
	spec := *plan.Relational
	spec.AdminPassword = st.adminPassword
	spec.Ingress = []compute.IngressRule{{
		From: compute.Peer{Kind: compute.PeerControlPlane}, Port: st.endpoint.Port,
	}}
	if err := m.checkpoint(ctx, app, "database-extensions"); err != nil {
		return err
	}
	// Ensure may apply the ingress and then return an error. Arrange cleanup
	// before calling it, not only after a successful response.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		spec.Ingress = nil
		_, cleanupErr := provisioner.EnsureRelational(cleanupCtx, spec)
		result = errors.Join(result, cleanupErr)
		if cleanupErr == nil {
			result = errors.Join(result, m.checkpoint(cleanupCtx, app, "database-extensions"))
		}
	}()
	if _, err := provisioner.EnsureRelational(ctx, spec); err != nil {
		return err
	}
	modules.ReportProgress(ctx, 65, "Installing PostgreSQL extensions")
	return m.installExtensions(ctx, st.endpoint, app.Database.AdminUsername, st.adminPassword,
		m.cfg.PostgresRootCertPath, app.Database.Extensions)
}

// adminPassword returns the database's administrative password: the one already
// stored if there is one, and a freshly generated one otherwise.
//
// The order is the interface's requirement and the reason this is not inline:
// the secret is stored *before* the database is provisioned, so that a
// provisioning failure leaves a password somebody can still use rather than an
// endpoint nobody can log into. And a redeploy never generates a new one,
// because the provider is forbidden from rotating on a re-Ensure and the stored
// copy would silently stop matching.
//
// It reads the stored value back, which is the one place this module handles
// material at all. It arrives as a [compute.SecretValue], which renders as
// "[REDACTED]" under every formatting verb, refuses to serialise, and is never
// converted to a string here.
func (m *Module) adminPassword(ctx context.Context, app *Application, binder *secretBinder) (compute.SecretValue, error) {
	if binder.store == nil {
		return compute.SecretValue{}, fmt.Errorf("%w: a relational database needs a secret store "+
			"to keep its administrative password in, and provider %q has none",
			compute.ErrUnsupported, m.provider.Name())
	}
	if ref, ok := binder.issued[EnvDatabasePassword]; ok {
		value, err := binder.store.Get(ctx, ref)
		if err != nil {
			return compute.SecretValue{}, fmt.Errorf("reading back the stored administrative "+
				"password: %w", err)
		}
		if value.IsZero() {
			return compute.SecretValue{}, fmt.Errorf("%w: the stored administrative password for "+
				"this application is empty; provisioning with a new one would leave the existing "+
				"database unreachable, so this is refused rather than repaired",
				ErrInvalidApplication)
		}
		return value, nil
	}
	generated, err := generatePassword()
	if err != nil {
		return compute.SecretValue{}, err
	}
	if err := m.checkpoint(ctx, app, "relational-database"); err != nil {
		return compute.SecretValue{}, err
	}
	if _, err := binder.put(ctx, EnvDatabasePassword, generated, secretLabels(app)); err != nil {
		return compute.SecretValue{}, err
	}
	app.Artifacts.Secrets = binder.refs()
	if err := m.checkpoint(ctx, app, "relational-database"); err != nil {
		return compute.SecretValue{}, err
	}
	return generated, nil
}

// secretLabels is the label set for a stored secret. Separate from the labels
// every other resource carries because a secret's labels are the one set that
// must be audited: the provider interface says labels are expected in listings
// and logs, so the application's display name — which a requester chooses — does
// not go on one.
func secretLabels(app *Application) map[string]string {
	return map[string]string{LabelApplication: app.ID}
}

// provisionKeyValue creates the table and grants the workload identity access.
func (m *Module) provisionKeyValue(ctx context.Context, plan *Plan, app *Application, st *runState) error {
	provisioner, err := m.provider.KeyValues()
	if err != nil {
		return err
	}
	modules.ReportProgress(ctx, 62, "Provisioning the key-value table")
	if err := m.checkpoint(ctx, app, "key-value-table"); err != nil {
		return err
	}
	status, err := provisioner.EnsureKeyValueTable(ctx, *plan.KeyValue)
	if status != nil {
		app.Artifacts.KeyValue = status.Ref
		st.tableName = status.Name
		err = errors.Join(err, m.checkpoint(ctx, app, "key-value-table"))
	}
	if err != nil {
		return err
	}
	if status.Phase != compute.PhaseReady {
		if status, err = provisioner.WaitForKeyValueTable(ctx, status.Ref, compute.WaitOptions{
			Timeout: m.cfg.waitTimeout(),
		}); err != nil {
			return err
		}
		st.tableName = status.Name
	}
	// A table the application cannot reach is a table it does not have.
	if err := m.checkpoint(ctx, app, "key-value-table"); err != nil {
		return err
	}
	err = provisioner.Grant(ctx, status.Ref, st.identity, compute.AccessReadWrite)
	return errors.Join(err, m.checkpoint(ctx, app, "key-value-table"))
}

// provisionBucket creates the bucket and grants the workload identity the level
// the application record asked for.
func (m *Module) provisionBucket(ctx context.Context, plan *Plan, app *Application, st *runState) error {
	store, err := m.provider.ObjectStores()
	if err != nil {
		return err
	}
	modules.ReportProgress(ctx, 64, "Provisioning object storage")
	if err := m.checkpoint(ctx, app, "object-store"); err != nil {
		return err
	}
	bucket, err := store.EnsureBucket(ctx, *plan.Bucket)
	if bucket != nil {
		app.Artifacts.Bucket = bucket.Ref
		st.bucketName, st.bucketURI = bucket.Name, bucket.URI
		err = errors.Join(err, m.checkpoint(ctx, app, "object-store"))
	}
	if err != nil {
		return err
	}
	if err := m.checkpoint(ctx, app, "object-store"); err != nil {
		return err
	}
	err = store.Grant(ctx, bucket.Ref, st.identity, plan.BucketAccess)
	return errors.Join(err, m.checkpoint(ctx, app, "object-store"))
}

// dataVar is one environment variable this module sets for a provisioned
// resource: its name, and how to read its value once the resource exists.
//
// Name and value live together so that the set of names a plan will occupy and
// the set it does occupy are one declaration. They used to be two -- the
// variables were built at apply time and nothing knew their names before then --
// which is why a record could ask for a variable this module was going to set
// and only find out during the deploy.
type dataVar struct {
	name  string
	value func(*Application, *runState) string
}

// dataVars is the environment a plan will set, derived from the plan.
//
// Not from the run state: the point is to know the names before anything is
// created. Values are read from the run state later, by [dataEnv].
func dataVars(p *Plan) []dataVar {
	var out []dataVar
	if p.Relational != nil {
		out = append(out,
			dataVar{EnvDatabaseHost, func(_ *Application, st *runState) string { return st.endpoint.Host }},
			dataVar{EnvDatabasePort, func(_ *Application, st *runState) string {
				return strconv.Itoa(st.endpoint.Port)
			}},
			dataVar{EnvDatabaseName, func(_ *Application, st *runState) string {
				return st.endpoint.DatabaseName
			}},
			dataVar{EnvDatabaseUser, func(a *Application, _ *runState) string {
				return a.Database.AdminUsername
			}},
		)
	}
	if p.KeyValue != nil {
		out = append(out, dataVar{EnvTableName, func(_ *Application, st *runState) string {
			return st.tableName
		}})
	}
	if p.Bucket != nil {
		out = append(out,
			dataVar{EnvBucketName, func(_ *Application, st *runState) string { return st.bucketName }},
			dataVar{EnvBucketURI, func(_ *Application, st *runState) string { return st.bucketURI }},
		)
	}
	return out
}

// dataEnvNames is what dataVars will occupy.
func dataEnvNames(p *Plan) []string {
	vars := dataVars(p)
	out := make([]string, 0, len(vars))
	for _, v := range vars {
		out = append(out, v.name)
	}
	return out
}

// dataEnv is the non-secret configuration a workload needs to reach what was
// provisioned for it.
//
// Host, port, database name and user are not secret and travel as environment
// variables. The source put all four in its secret store as well
// (container.go:586-590), for the stated reason that they would then be visible
// in its own UI -- which put four non-secret values behind the same access path
// as the password and made every one of them a thing a redeploy could clobber.
//
// A variable whose value came back empty is dropped rather than set to nothing,
// and that is not a shrug: a provider that reported a resource ready without an
// endpoint has already failed its own contract, and setting DATABASE_HOST to ""
// would hand the workload a value that looks configured.
func dataEnv(p *Plan, app *Application, st *runState) []compute.EnvVar {
	var env []compute.EnvVar
	for _, v := range dataVars(p) {
		if value := v.value(app, st); value != "" {
			env = append(env, compute.EnvVar{Name: v.name, Value: value})
		}
	}
	return env
}

// workloadInputs assembles the secret bindings and the identity materials.
func (m *Module) workloadInputs(ctx context.Context, plan *Plan, app *Application, st *runState) ([]compute.SecretBinding, string, error) {
	var bindings []compute.SecretBinding
	binder := st.binder

	if plan.Relational != nil {
		// No pin: the database password is minted and rotated by this module, so
		// the revision a workload wants is always the current one. Pinning it to
		// the revision this deploy wrote would freeze the next rotation out.
		binding, err := binder.bindName(EnvDatabasePassword, EnvDatabasePassword, "")
		if err != nil {
			return nil, "secret-binding", err
		}
		bindings = append(bindings, binding)
	}
	bindings = append(bindings, plan.Secrets...)
	envBindings, err := envSecretBindings(app, binder)
	if err != nil {
		return nil, "secret-binding", err
	}
	bindings = append(bindings, envBindings...)
	if m.cfg.WorkloadIdentityMode == "native" {
		return bindings, "", nil
	}

	// Workload identity. Rotate on every deploy, then ask for the materials
	// with the revision rotate returned: the sequence is fixed by the
	// workload-identity contract, and rotating bounds a leaked attestation
	// secret to the time until the next deployment.
	modules.ReportProgress(ctx, 70, "Rotating workload attestation")
	if err := m.checkpoint(ctx, app, "attestation-rotate"); err != nil {
		return nil, "attestation-rotate", err
	}
	revision, err := m.attestations.Rotate(ctx, workload.Ref{ApplicationID: app.ID})
	if revision > 0 {
		app.Artifacts.AttestationRevision = revision
		err = errors.Join(err, m.checkpoint(ctx, app, "attestation-rotate"))
	}
	if err != nil {
		return nil, "attestation-rotate", err
	}
	if err := m.checkpoint(ctx, app, "attestation-materials"); err != nil {
		return nil, "attestation-materials", err
	}
	materials, err := m.attestations.Materials(ctx, workload.Ref{ApplicationID: app.ID, Revision: revision})
	if err != nil {
		return nil, "attestation-materials", err
	}
	for _, ref := range materials.Secrets {
		binding, err := binder.bind(ref)
		if err != nil {
			return nil, "attestation-materials", err
		}
		bindings = append(bindings, binding)
	}
	st.materialsEnv = materials.Env
	if err := m.checkpoint(ctx, app, "attestation-materials"); err != nil {
		return nil, "attestation-materials", err
	}
	return bindings, "", nil
}

// startWorkload creates the service or the scheduled job and waits for it.
func (m *Module) startWorkload(ctx context.Context, plan *Plan, app *Application, st *runState, r resolved) (string, error) {
	// Materials env is set verbatim, after this module's own, and a collision
	// is refused rather than resolved: two values for one variable means one of
	// them is silently discarded, and which one is not something to decide by
	// map iteration order.
	seen := map[string]bool{}
	for _, e := range r.env {
		seen[e.Name] = true
	}
	for _, name := range app.EnvSecrets {
		seen[name] = true
	}
	for name, value := range st.materialsEnv {
		if seen[name] {
			return "workload", fmt.Errorf("%w: workload identity material and this module or an "+
				"environment secret both set %q", ErrInvalidApplication, name)
		}
		seen[name] = true
		r.env = append(r.env, compute.EnvVar{Name: name, Value: value})
	}
	sortEnv(r.env)

	runtime, err := m.provider.Containers()
	if err != nil {
		return "workload", err
	}
	if step, err := m.retirePreviousWorkload(ctx, runtime, app); err != nil {
		return step, err
	}

	if app.Execution == ExecutionScheduled {
		modules.ReportProgress(ctx, 80, "Creating the scheduled job")
		if err := m.checkpoint(ctx, app, "scheduled-job"); err != nil {
			return "scheduled-job", err
		}
		status, err := runtime.EnsureScheduledJob(ctx, plan.ScheduledJob(r))
		if status != nil {
			app.Artifacts.Workload = status.Ref
			app.Artifacts.Addresses = nil
			err = errors.Join(err, m.checkpoint(ctx, app, "scheduled-job"))
		}
		if err != nil {
			return "scheduled-job", err
		}
		return "", nil
	}

	modules.ReportProgress(ctx, 80, "Starting the workload")
	if err := m.checkpoint(ctx, app, "service"); err != nil {
		return "service", err
	}
	spec := plan.Service(r)
	status, err := runtime.EnsureService(ctx, spec)
	if status != nil {
		app.Artifacts.Workload = status.Ref
		app.Artifacts.Addresses = tlsRouteAddresses(plan.Routes, status.RouteAddresses)
		err = errors.Join(err, m.checkpoint(ctx, app, "service"))
	}
	if err != nil {
		return "service", err
	}

	modules.ReportProgress(ctx, 90, "Waiting for the workload to become ready")
	if err := m.checkpoint(ctx, app, "service-ready"); err != nil {
		return "service-ready", err
	}
	if _, err := runtime.WaitForService(ctx, status.Ref, spec.Replicas, compute.WaitOptions{
		Timeout: m.cfg.waitTimeout(),
	}); err != nil {
		return "service-ready", err
	}
	status, err = runtime.DescribeService(ctx, status.Ref)
	if err != nil {
		return "service-ready", err
	}
	app.Artifacts.Addresses = tlsRouteAddresses(plan.Routes, status.RouteAddresses)
	return "service-ready", m.checkpoint(ctx, app, "service-ready")
}

const (
	stepWorkloadRetire      = "workload-retire"
	stepWorkloadRetireReady = "workload-retire-ready"
)

// retirePreviousWorkload prevents a service and schedule for one application
// from remaining active together after an execution-mode change. Keep the old
// reference through every uncertain outcome; only a confirmed removal permits
// replacing it with the new workload.
func (m *Module) retirePreviousWorkload(ctx context.Context, runtime compute.ContainerRuntime, app *Application) (string, error) {
	prior := app.Artifacts.Workload
	wanted := compute.KindService
	if app.Execution == ExecutionScheduled {
		wanted = compute.KindScheduledJob
	}
	if prior.IsZero() || prior.Kind == wanted {
		return "", nil
	}
	if prior.Kind != compute.KindService && prior.Kind != compute.KindScheduledJob {
		return stepWorkloadRetire, fmt.Errorf("%w: cannot retire workload kind %q", ErrInvalidApplication, prior.Kind)
	}
	if err := m.checkpoint(ctx, app, stepWorkloadRetire); err != nil {
		return stepWorkloadRetire, err
	}
	var err error
	if prior.Kind == compute.KindService {
		err = runtime.DeleteService(ctx, prior)
	} else {
		err = runtime.DeleteScheduledJob(ctx, prior)
	}
	if err != nil {
		return stepWorkloadRetire, err
	}
	if err := m.checkpoint(ctx, app, stepWorkloadRetireReady); err != nil {
		return stepWorkloadRetireReady, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, m.cfg.waitTimeout())
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := waitCtx.Err(); err != nil {
			return stepWorkloadRetireReady, errors.Join(compute.ErrTimeout, err)
		}
		gone := false
		if prior.Kind == compute.KindService {
			status, err := runtime.DescribeService(waitCtx, prior)
			if err != nil {
				return stepWorkloadRetireReady, err
			}
			if status == nil {
				return stepWorkloadRetireReady, fmt.Errorf("%w: service removal returned no status", compute.ErrInvalidSpec)
			}
			gone = status.Phase == compute.PhaseGone
		} else {
			_, err := runtime.DescribeScheduledJob(waitCtx, prior)
			gone = errors.Is(err, compute.ErrNotFound)
			if err != nil && !gone {
				return stepWorkloadRetireReady, err
			}
		}
		if gone {
			break
		}
		select {
		case <-waitCtx.Done():
			return stepWorkloadRetireReady, errors.Join(compute.ErrTimeout, waitCtx.Err())
		case <-ticker.C:
		}
	}
	app.Artifacts.Workload = compute.Ref{}
	app.Artifacts.Addresses = nil
	if err := m.checkpoint(ctx, app, stepWorkloadRetireReady); err != nil {
		app.Artifacts.Workload = prior
		return stepWorkloadRetireReady, err
	}
	return "", nil
}

// tlsRouteAddresses turns only operator-configured TLS route hosts actually
// reported by the provider into portal links. An ingress controller address is
// not itself a published application route, and provider URLs cannot introduce
// arbitrary destinations, credentials, paths, queries or fragments.
func tlsRouteAddresses(routes []compute.Route, reported []string) []string {
	var addresses []string
	for _, route := range routes {
		if route.TLS == nil || route.AllowPlaintext || route.TLS.CertificateRef == "" {
			continue
		}
		for _, address := range reported {
			if !strings.Contains(address, "://") {
				address = "https://" + address
			}
			u, err := url.Parse(address)
			if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" ||
				u.Host == "" || u.Port() != "" || !strings.EqualFold(u.Host, route.Host) ||
				(u.Path != "" && u.Path != "/") || u.RawPath != "" ||
				u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
				continue
			}
			addresses = append(addresses, "https://"+strings.ToLower(route.Host))
			break
		}
	}
	return addresses
}

// deployTag is an immutable per-deploy image tag.
//
// Random rather than derived from the application, and that is the point: the
// source tagged every build of an application "deploy-<first eight characters
// of its id>" (container.go:205-206), so two deploys of one application pushed
// different content to the same reference and a rollback had nothing to roll
// back to.
func deployTag() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating an image tag: %w", err)
	}
	return "deploy-" + hexOf(buf), nil
}

// passwordAlphabet is what a generated administrative password is drawn from.
//
// Alphanumerics only, which is a deliberate restriction rather than an
// oversight: the password ends up in connection strings assembled by
// applications this platform does not control, and a byte that needs escaping
// in a URL is a byte that eventually is not escaped. 62 symbols over 32
// characters is a little over 190 bits.
const passwordAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// passwordLength matches the source's (container.go:302).
const passwordLength = 32

// generatePassword draws a password from crypto/rand.
func generatePassword() (compute.SecretValue, error) {
	return generatePasswordFrom(rand.Read)
}

// passwordByteLimit is the largest multiple of the alphabet size that fits in a
// byte. A byte at or above it is discarded rather than folded.
const passwordByteLimit = 256 - (256 % len(passwordAlphabet))

// generatePasswordFrom is [generatePassword] over a supplied byte source.
//
// The source is a parameter so that the rejection rule can be tested for what
// it is — a deterministic property of which bytes are accepted — rather than by
// sampling the output and looking for a skew. A distribution test would have to
// pick a threshold, and a threshold tuned to a quiet machine is a flake wearing
// a justification; worse, the loose threshold that is not a flake does not
// notice the bias it exists to detect. Measured: the naive form makes eight of
// sixty-two symbols about 25% more likely, which no honest sampling bound
// separates from noise at a test's sample size.
//
// It is unexported and takes no interface, so there is no way for a caller
// outside this package to substitute a weaker source.
//
// 62 does not divide 256, so folding every byte with a modulo would make the
// first eight symbols of the alphabet more likely than the rest. Bytes at or
// above [passwordByteLimit] are therefore discarded, not folded.
func generatePasswordFrom(read func([]byte) (int, error)) (compute.SecretValue, error) {
	out := make([]byte, 0, passwordLength)
	buf := make([]byte, passwordLength)
	for len(out) < passwordLength {
		if _, err := read(buf); err != nil {
			return compute.SecretValue{}, fmt.Errorf("generating a password: %w", err)
		}
		for _, b := range buf {
			if int(b) >= passwordByteLimit {
				continue
			}
			out = append(out, passwordAlphabet[int(b)%len(passwordAlphabet)])
			if len(out) == passwordLength {
				break
			}
		}
	}
	return compute.NewSecretValue(string(out)), nil
}

const hexDigits = "0123456789abcdef"

func hexOf(b []byte) string {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0f])
	}
	return string(out)
}

// sortEnv puts environment variables in a deterministic order, so two deploys
// of an unchanged application produce an identical specification and a provider
// that compares revisions does not see a change that is not one.
func sortEnv(env []compute.EnvVar) {
	for i := 1; i < len(env); i++ {
		for j := i; j > 0 && env[j].Name < env[j-1].Name; j-- {
			env[j], env[j-1] = env[j-1], env[j]
		}
	}
}
