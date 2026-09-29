// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/conductorone/apphub/modules"
)

// ModuleID is the identifier this module registers and is invoked under. It is
// the source's identifier unchanged: [modules.Module] requires it to be stable
// across releases because it is persisted on stored work, and an adopter
// migrating from the source has stored work under this string.
const ModuleID = "agentic-repo-scan"

// Mode selects how the source is reached.
type Mode string

const (
	// ModeInstallation reads the repository as an installed application. It
	// requires an installation identifier and can reach private repositories
	// the installation was granted.
	ModeInstallation Mode = "installation"
	// ModePublic reads the repository unauthenticated. It reaches only public
	// repositories, at whatever budget the host gives anonymous callers.
	ModePublic Mode = "public"
)

// Modes returns the two modes, in the order the schema publishes them.
func Modes() []Mode { return []Mode{ModeInstallation, ModePublic} }

// Suggested values for [Limits]. They are suggestions and not defaults:
// [New] has no default for either field and refuses a zero, so a caller
// chooses these deliberately or chooses something else.
const (
	// SuggestedMaxSourceBytes is the snapshot cap the source shipped.
	SuggestedMaxSourceBytes int64 = 100 << 20
	// SuggestedTerminalWriteTimeout bounds a terminal write to the store.
	SuggestedTerminalWriteTimeout = 30 * time.Second
)

// Limits are the bounds a scan runs under.
//
// They are values on the constructor rather than something resolved per run.
// The source resolved them at execution time from an administrative record and
// fell back to a compiled constant whenever that read failed, which means a
// storage outage silently changed the cap a scan ran under. A bound that can
// change because something unrelated broke is not a bound. A caller that wants
// live reconfiguration builds a module with the new limits; nothing here reads
// configuration.
type Limits struct {
	// MaxSourceBytes caps the decompressed size of a snapshot. Must be
	// positive.
	MaxSourceBytes int64
	// TerminalWriteTimeout bounds each write that moves the record to a
	// terminal state. These writes run on a fresh context precisely because
	// the scan's own context may already be cancelled by the time one is
	// needed, so they need a deadline of their own. Must be positive.
	TerminalWriteTimeout time.Duration
}

// Module scans a repository and reports findings. Construct it with [New].
type Module struct {
	modules.BaseModule

	scanner Scanner
	source  SourceFetcher
	store   ResultStore
	log     *slog.Logger
	limits  Limits
}

// Compile-time proof that the module satisfies the framework contract.
var _ modules.Module = (*Module)(nil)

// New builds the module.
//
// Every dependency is required and a nil one is refused here, wrapped in
// [modules.ErrNotConfigured], rather than checked on each execution. That is
// the framework's convention and the reason for it is visible in what this
// function replaces: the source constructed this module empty, registered it,
// and pushed five dependencies in afterwards, so it carried four hand-written
// "not configured" branches inside its execution path and a fifth dependency
// that quietly built itself a substitute when absent. A module that cannot be
// constructed unwired needs none of that.
func New(scanner Scanner, source SourceFetcher, store ResultStore, logger *slog.Logger, limits Limits) (*Module, error) {
	// modules.Absent rather than `== nil`: an interface holding a nil pointer
	// is not nil, so a plain comparison accepts a typed nil, returns a module
	// that looks wired, and panics on its first call.
	switch {
	case modules.Absent(scanner):
		return nil, modules.Missing(ModuleID, "scanner")
	case modules.Absent(source):
		return nil, modules.Missing(ModuleID, "source fetcher")
	case modules.Absent(store):
		return nil, modules.Missing(ModuleID, "result store")
	case modules.Absent(logger):
		return nil, modules.Missing(ModuleID, "logger")
	case limits.MaxSourceBytes <= 0:
		return nil, modules.Missing(ModuleID, "a positive Limits.MaxSourceBytes")
	case limits.TerminalWriteTimeout <= 0:
		return nil, modules.Missing(ModuleID, "a positive Limits.TerminalWriteTimeout")
	}
	return &Module{
		BaseModule: modules.NewBaseModule(
			ModuleID,
			"Agentic Repo Scan",
			"Run an agent-driven security review against a repository and record what it finds.",
			"travel_explore",
			"Security",
		),
		scanner: scanner,
		source:  source,
		store:   store,
		log:     logger.With(slog.String("module", ModuleID)),
		limits:  limits,
	}, nil
}

// Execute runs one scan end to end.
//
// The findings are the point and they go to the store, not into the returned
// [modules.Result]: the record is the artefact, and Data carries only enough
// for a caller watching a generic job list to say something useful.
//
// Both return values are meaningful independently, per [modules.Module]. In
// particular the two "the record was deleted while we worked" paths return a
// successful Result with a nil error, because nothing failed -- the work was
// simply no longer wanted.
func (m *Module) Execute(ctx context.Context, userID string, params map[string]any) (*modules.Result, error) {
	if err := m.Validate(params); err != nil {
		return nil, err
	}
	req, err := m.readRequest(params)
	if err != nil {
		return nil, err
	}
	log := m.log.With(slog.String("scanId", req.scanID))

	// fail moves the record to its terminal failure state on a context of its
	// own. userMessage is read by the person who asked for the scan, so it
	// says what they can do about it and never carries an upstream response.
	fail := func(userMessage string) {
		fc, cancel := m.terminalCtx()
		defer cancel()
		if err := m.store.Fail(fc, req.scanID, userMessage); err != nil {
			if errors.Is(err, ErrRecordNotFound) {
				return
			}
			log.ErrorContext(ctx, "could not record scan failure", slog.Any("error", err))
		}
	}

	if gone, err := m.markRunning(ctx, log, req.scanID); err != nil {
		return nil, err
	} else if gone != nil {
		return gone, nil
	}

	modules.ReportProgress(ctx, 15, "Downloading repository snapshot")
	snapshot, err := m.source.Fetch(ctx, req.at, m.limits.MaxSourceBytes)
	if err != nil {
		log.ErrorContext(ctx, "could not fetch repository snapshot", slog.Any("error", err))
		fail(m.fetchMessage(err, req.at))
		return nil, err
	}
	// A snapshot that cannot say which revision it is, or that carries no
	// contents, is refused rather than used. Both are the fetcher failing to
	// hold up its end, and neither is something to work around here.
	switch {
	case snapshot == nil:
		err := fmt.Errorf("%s: source fetcher returned no snapshot and no error", ModuleID)
		log.ErrorContext(ctx, "source fetcher returned no snapshot and no error")
		fail("Failed to download the repository snapshot")
		return nil, err
	case snapshot.Tree == nil:
		err := fmt.Errorf("%s: source fetcher returned a snapshot with no contents", ModuleID)
		log.ErrorContext(ctx, "source fetcher returned a snapshot with no contents")
		fail("Failed to download the repository snapshot")
		return nil, err
	case snapshot.Commit == "":
		err := fmt.Errorf("%s: source fetcher returned a snapshot that names no revision", ModuleID)
		log.ErrorContext(ctx, "source fetcher returned a snapshot that names no revision")
		fail("Failed to download the repository snapshot")
		return nil, err
	}
	modules.ReportProgress(ctx, 35, fmt.Sprintf("Snapshot ready: %d files", len(snapshot.Tree.List())))

	modules.ReportProgress(ctx, 45, fmt.Sprintf("Running %s scan", req.depth))
	res, err := m.scanner.Scan(ctx, ScanRequest{
		Depth: req.depth,
		Tree:  snapshot.Tree,
		Owner: req.at.Owner,
		Repo:  req.at.Repo,
		Ref:   req.at.Ref,
	})
	if err != nil {
		log.ErrorContext(ctx, "scan failed", slog.Any("error", err))
		// A scan can spend before it fails. Book what it spent: the ledger is
		// about what we were billed, which is not conditional on the outcome.
		if res != nil && !res.Cost.Empty() {
			m.recordPartialCost(ctx, log, req.scanID, res.Cost)
		}
		fail("The scanner failed to produce findings")
		return nil, err
	}
	if res == nil {
		err := fmt.Errorf("%s: scanner returned no result and no error", ModuleID)
		log.ErrorContext(ctx, "scanner returned no result and no error")
		fail("The scanner failed to produce findings")
		return nil, err
	}

	findings := make([]Finding, 0, len(res.Findings))
	for _, f := range res.Findings {
		findings = append(findings, f.Sanitise())
	}
	modules.ReportProgress(ctx, 90, fmt.Sprintf("Recording %d findings", len(findings)))

	completion := Completion{
		Owner:           req.at.Owner,
		Repo:            req.at.Repo,
		Ref:             req.at.Ref,
		Commit:          snapshot.Commit,
		Findings:        findings,
		HighestSeverity: HighestSeverity(findings),
		Cost:            res.Cost,
		Iterations:      res.Iterations,
		BytesRead:       res.BytesRead,
	}
	cc, cancel := m.terminalCtx()
	defer cancel()
	if err := m.store.Complete(cc, req.scanID, completion); err != nil {
		if errors.Is(err, ErrRecordNotFound) {
			log.InfoContext(ctx, "scan record deleted mid-run; dropping result")
			return &modules.Result{Success: true, Message: "Scan cancelled: the record was deleted while it ran"}, nil
		}
		return nil, fmt.Errorf("%s: record findings: %w", ModuleID, err)
	}

	modules.ReportProgress(ctx, 100, fmt.Sprintf("Done: %d findings", len(findings)))
	return &modules.Result{
		Success: true,
		Message: fmt.Sprintf("Scanned %s/%s (%s): %d findings", req.at.Owner, req.at.Repo, req.depth, len(findings)),
		Data: map[string]any{
			"scanId":              req.scanID,
			"owner":               req.at.Owner,
			"repo":                req.at.Repo,
			"ref":                 req.at.Ref,
			"mode":                string(req.mode),
			"scanType":            string(req.depth),
			"findingsCount":       len(findings),
			"highestSeverity":     string(completion.HighestSeverity),
			"commit":              snapshot.Commit,
			"iterations":          res.Iterations,
			"bytesRead":           res.BytesRead,
			"installationId":      req.at.InstallationID,
			"requestedBy":         userID,
			"model":               res.Cost.Model,
			"inputTokens":         res.Cost.Usage.InputTokens,
			"outputTokens":        res.Cost.Usage.OutputTokens,
			"llmCallCount":        res.Cost.Usage.Calls,
			"estimatedCostMicros": res.Cost.EstimatedCostMicros,
		},
	}, nil
}

// markRunning moves the record out of pending before anything expensive
// starts. It returns a non-nil Result when the record is gone, which is a
// successful outcome and not a failure.
func (m *Module) markRunning(ctx context.Context, log *slog.Logger, scanID string) (*modules.Result, error) {
	modules.ReportProgress(ctx, 5, "Starting scan")
	mc, cancel := m.terminalCtx()
	defer cancel()
	err := m.store.MarkRunning(mc, scanID)
	switch {
	case err == nil:
		return nil, nil
	case errors.Is(err, ErrRecordNotFound):
		log.InfoContext(ctx, "scan record deleted before the run started")
		return &modules.Result{Success: true, Message: "Scan cancelled: the record was deleted before it started"}, nil
	default:
		// Deliberately not fatal, and deliberately not silent. The scan can
		// still do its work and its terminal write can still land; the only
		// casualty is that a reader sees "pending" until it does.
		log.WarnContext(ctx, "could not mark the scan running", slog.Any("error", err))
		return nil, nil
	}
}

func (m *Module) recordPartialCost(ctx context.Context, log *slog.Logger, scanID string, cost Cost) {
	pc, cancel := m.terminalCtx()
	defer cancel()
	if err := m.store.RecordPartialCost(pc, scanID, cost); err != nil && !errors.Is(err, ErrRecordNotFound) {
		log.ErrorContext(ctx, "could not record partial scan cost", slog.Any("error", err))
	}
}

// terminalCtx returns a fresh context for a write that must land.
//
// It deliberately does not derive from the scan's context. A scan that ran out
// of time or was cancelled still has to move its record out of running, and a
// derived context is already expired at exactly the moment that matters --
// which leaves the record in running for ever and a reader polling it for ever.
func (m *Module) terminalCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), m.limits.TerminalWriteTimeout)
}

// fetchMessage turns a fetch failure into something the requester can act on.
//
// The forbidden case is split by mode because the same status means different
// things: authenticated, the installation is missing a grant on this
// repository; unauthenticated, it is almost always a rate limit. The source
// reported the first message in both cases, which sent every public scan to
// look for a permission that was never involved.
func (m *Module) fetchMessage(err error, at Coordinates) string {
	switch {
	case errors.Is(err, ErrSourceNotFound):
		return "Repository or ref not found"
	case errors.Is(err, ErrSourceTooLarge):
		return fmt.Sprintf("Repository snapshot exceeds the %d MiB cap", m.limits.MaxSourceBytes>>20)
	case errors.Is(err, ErrSourceForbidden):
		if at.Authenticated() {
			return "The source host denied the download; the installation may lack read access to this repository"
		}
		return "The source host denied the unauthenticated download; it is most likely rate limited, so retry later or run through an installation"
	default:
		return "Failed to download the repository snapshot"
	}
}

// request is the validated, defaulted form of the parameter map.
type request struct {
	scanID string
	mode   Mode
	depth  Depth
	at     Coordinates
}

func (m *Module) readRequest(params map[string]any) (request, error) {
	scanID, ok := StringParam(params, "scanId")
	if !ok {
		return request{}, fmt.Errorf("scanId is required")
	}
	owner, _ := params["owner"].(string)
	repo, _ := params["repo"].(string)
	ref, _ := params["ref"].(string)
	installationID, _ := PositiveIntParam(params, "installationId")
	mode := modeOf(params)
	if mode == ModePublic {
		// Public mode is unauthenticated by definition. Dropping the
		// identifier here rather than trusting the caller not to send one is
		// what makes "public means anonymous" a property of the code: a
		// public-mode scan cannot borrow an installation's authorisation even
		// if a caller asks it to.
		installationID = 0
	}
	return request{
		scanID: scanID,
		mode:   mode,
		depth:  depthOf(params),
		at: Coordinates{
			Owner:          owner,
			Repo:           repo,
			Ref:            ref,
			InstallationID: installationID,
		},
	}, nil
}

// modeOf and depthOf apply the schema's declared defaults. They are the single
// place each default is applied, so Validate and Execute cannot disagree about
// what an absent parameter means.
func modeOf(params map[string]any) Mode {
	s, _ := params["mode"].(string)
	if s == "" {
		return ModeInstallation
	}
	return Mode(s)
}

func depthOf(params map[string]any) Depth {
	s, _ := params["scanType"].(string)
	if s == "" {
		return DepthQuick
	}
	return Depth(s)
}

// Validate reports whether params are acceptable, without executing.
func (m *Module) Validate(params map[string]any) error {
	if err := modules.ValidateDeclaredParams(m.Schema(), params); err != nil {
		return err
	}
	if _, ok := StringParam(params, "scanId"); !ok {
		return fmt.Errorf("scanId is required: it names the record to write findings to")
	}
	switch mode := modeOf(params); mode {
	case ModeInstallation:
		if _, ok := PositiveIntParam(params, "installationId"); !ok {
			return fmt.Errorf("installationId is required and must be a positive integer in %s mode", ModeInstallation)
		}
	case ModePublic:
	default:
		return fmt.Errorf("mode must be %q or %q", ModeInstallation, ModePublic)
	}
	switch depth := depthOf(params); depth {
	case DepthQuick, DepthDeep:
	default:
		return fmt.Errorf("scanType must be %q or %q", DepthQuick, DepthDeep)
	}
	owner, _ := params["owner"].(string)
	repo, _ := params["repo"].(string)
	if err := ValidateOwnerRepo(owner, repo); err != nil {
		return err
	}
	if ref, ok := params["ref"].(string); ok && ref != "" && !IsSafeRef(ref) {
		return fmt.Errorf("ref contains invalid characters or exceeds %d characters", MaxRefLen)
	}
	return nil
}

// Schema is the module's published parameter contract.
func (m *Module) Schema() *modules.JSONSchema {
	return &modules.JSONSchema{
		Type: "object",
		Properties: map[string]modules.JSONSchemaProperty{
			"scanId": {
				Type:        "string",
				Description: "Identifier of the record to write findings to. The caller creates it before invoking this module.",
			},
			"mode": {
				Type:        "string",
				Enum:        enumOf(Modes()),
				Default:     string(ModeInstallation),
				Description: "installation: read as an installed application. public: read anonymously, public repositories only.",
			},
			"installationId": {
				Type:        "integer",
				Description: "Installation with access to the repository. Required when mode is installation, ignored when it is public.",
				Minimum:     ptr(1),
			},
			"scanType": {
				Type:        "string",
				Enum:        enumOf(Depths()),
				Default:     string(DepthQuick),
				Description: "scan-quick: one pass over a curated bundle. scan-deep: an agentic loop, more thorough and more expensive.",
			},
			"owner": {
				Type:        "string",
				Description: "Repository owner.",
			},
			"repo": {
				Type:        "string",
				Description: "Repository name, without the owner.",
			},
			"ref": {
				Type:        "string",
				Description: "Revision to scan: a branch, tag or commit. Defaults to the repository's default branch.",
			},
		},
		Required: []string{"scanId", "owner", "repo"},
	}
}

// enumOf renders a typed enumeration as the schema's string form. It is
// derived from the same slice the validator switches on, so a value added to
// one is published by the other.
func enumOf[T ~string](values []T) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, string(v))
	}
	return out
}

func ptr[T any](v T) *T { return &v }
