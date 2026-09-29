// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/conductorone/apphub/modules"
	"github.com/conductorone/apphub/modules/review"
)

// ModuleID is the identifier this module registers and is invoked under,
// unchanged from the source for the same reason as [review.ModuleID].
const ModuleID = "agentic-fix-pr"

// maxBranchAttempts bounds the collision retry when creating the branch. The
// name already contains a scan identifier and a finding index, so a collision
// means somebody created that branch by hand; a few retries covers the case
// and anything beyond it is a person, not a race.
const maxBranchAttempts = 5

// identityNameRE bounds the name that goes into every artefact this module
// creates. It has to be safe as a ref namespace, as a label, and inside
// markup, so it is the intersection: alphanumerics and hyphens, starting with
// an alphanumeric.
var identityNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)

// maxIdentityNameLen bounds it, so a branch name is a branch name.
const maxIdentityNameLen = 39

// recordIDRE bounds the two identifiers a caller supplies.
//
// The scan identifier is spliced into a branch name, which means a caller
// chooses part of a ref this module creates in somebody else's repository. The
// source did not check it because its identifier came from its own storage;
// here it arrives in a parameter map, so it is checked. A ref may not contain
// a space, "..", "~", "^", ":", "?", "*", "[", "\" or a component ending
// ".lock", and rather than enumerate that list -- which is a grammar, and the
// next character is always available -- this admits a closed set that contains
// none of them.
var recordIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// maxRecordIDLen bounds those identifiers.
const maxRecordIDLen = 128

// Identity names the automation in the repositories it writes to.
//
// Every artefact carries it: the branch namespace, the commit title prefix,
// the pull request label, and the sentences in the pull request body that say
// where this came from. It has no default. A person reviewing an unexpected
// pull request needs to know who opened it, and this repository cannot know
// what to call the person running it.
type Identity struct {
	// Name is a short slug. It must match [A-Za-z0-9][A-Za-z0-9-]* and be at
	// most 39 characters.
	Name string
}

// Validate checks the identity.
func (i Identity) Validate() error {
	if i.Name == "" {
		return fmt.Errorf("identity name is required")
	}
	if len(i.Name) > maxIdentityNameLen {
		return fmt.Errorf("identity name exceeds %d characters", maxIdentityNameLen)
	}
	if !identityNameRE.MatchString(i.Name) {
		return fmt.Errorf("identity name must be alphanumerics and hyphens, starting with an alphanumeric")
	}
	return nil
}

// Module validates one finding and, when it holds up, opens a draft pull
// request fixing it. Construct it with [New].
type Module struct {
	modules.BaseModule

	fixer  Fixer
	source review.SourceFetcher
	git    GitClient
	scans  ScanReader
	store  ResultStore
	log    *slog.Logger

	identity Identity
	limits   Limits
	// maxSourceBytes bounds the snapshot fetch, as in modules/review.
	maxSourceBytes int64
}

var _ modules.Module = (*Module)(nil)

// Config is what [New] needs. It is a struct rather than a parameter list
// because there are nine of them and a positional call of that length is a
// place to put an argument in the wrong slot.
type Config struct {
	// Fixer validates findings and drafts patches.
	Fixer Fixer
	// Source fetches the repository snapshot.
	Source review.SourceFetcher
	// Git writes the branch, commit and pull request.
	Git GitClient
	// Scans reads the completed scan the finding comes from.
	Scans ScanReader
	// Store is the record this module reports into.
	Store ResultStore
	// Logger receives what is not returned: best-effort writes that failed,
	// and everything a person triaging a run needs that the requester must not
	// see.
	Logger *slog.Logger
	// Identity names the automation. Required, no default.
	Identity Identity
	// Limits bound a proposed patch. Every field is required.
	Limits Limits
	// MaxSourceBytes bounds the snapshot fetch. Required and positive.
	MaxSourceBytes int64
}

// New builds the module. Every dependency is required and a missing one is
// refused here, wrapped in [modules.ErrNotConfigured], so a constructed module
// is a wired module.
func New(cfg Config) (*Module, error) {
	// modules.Absent rather than `== nil`, for the reason recorded there: a
	// typed nil satisfies a nil comparison and panics later.
	switch {
	case modules.Absent(cfg.Fixer):
		return nil, modules.Missing(ModuleID, "fixer")
	case modules.Absent(cfg.Source):
		return nil, modules.Missing(ModuleID, "source fetcher")
	case modules.Absent(cfg.Git):
		return nil, modules.Missing(ModuleID, "git client")
	case modules.Absent(cfg.Scans):
		return nil, modules.Missing(ModuleID, "scan reader")
	case modules.Absent(cfg.Store):
		return nil, modules.Missing(ModuleID, "result store")
	case modules.Absent(cfg.Logger):
		return nil, modules.Missing(ModuleID, "logger")
	}
	if err := cfg.Identity.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", modules.Missing(ModuleID, "a valid identity"), err)
	}
	switch {
	case cfg.Limits.MaxFiles <= 0:
		return nil, modules.Missing(ModuleID, "a positive Limits.MaxFiles")
	case cfg.Limits.MaxLines <= 0:
		return nil, modules.Missing(ModuleID, "a positive Limits.MaxLines")
	case cfg.Limits.MaxBytesPerFile <= 0:
		return nil, modules.Missing(ModuleID, "a positive Limits.MaxBytesPerFile")
	case cfg.Limits.MaxEncodedPatchBytes <= 0:
		return nil, modules.Missing(ModuleID, "a positive Limits.MaxEncodedPatchBytes")
	case cfg.Limits.TerminalWriteTimeout <= 0:
		return nil, modules.Missing(ModuleID, "a positive Limits.TerminalWriteTimeout")
	case cfg.MaxSourceBytes <= 0:
		return nil, modules.Missing(ModuleID, "a positive MaxSourceBytes")
	}
	return &Module{
		BaseModule: modules.NewBaseModule(
			ModuleID,
			"Agentic Fix PR",
			"Validate one security finding against the repository and, when it holds up, open a draft pull request fixing it.",
			"auto_fix_high",
			"Security",
		),
		fixer:          cfg.Fixer,
		source:         cfg.Source,
		git:            cfg.Git,
		scans:          cfg.Scans,
		store:          cfg.Store,
		log:            cfg.Logger.With(slog.String("module", ModuleID)),
		identity:       cfg.Identity,
		limits:         cfg.Limits,
		maxSourceBytes: cfg.MaxSourceBytes,
	}, nil
}

// run carries the state one execution accumulates. It exists because the cost
// ledger and the failure writer have to see the same accumulated spend, and
// threading both through fifteen call sites is how one of them ends up seeing
// a stale copy.
type run struct {
	m     *Module
	log   *slog.Logger
	fixID string

	cost review.Cost
	// booked guards against writing the cost twice. The running totals a store
	// keeps are additive, so a second write over-counts even where the record
	// itself is idempotent. Every terminal path goes through this.
	booked bool
}

// spend accumulates one step's cost. The model is taken from the first step
// that names one, because the two steps run against the same model and the
// second may fail before it has one to report.
func (r *run) spend(c review.Cost) {
	r.cost.Usage.Add(c.Usage)
	r.cost.EstimatedCostMicros += c.EstimatedCostMicros
	if r.cost.Model == "" {
		r.cost.Model = c.Model
	}
}

// book writes the accumulated cost, once.
func (r *run) book(ctx context.Context) {
	if r.booked {
		return
	}
	r.booked = true
	if r.cost.Empty() {
		return
	}
	bc, cancel := r.m.terminalCtx()
	defer cancel()
	if err := r.m.store.RecordCost(bc, r.fixID, r.cost); err != nil && !errors.Is(err, ErrRecordNotFound) {
		r.log.ErrorContext(ctx, "could not record fix cost", slog.Any("error", err))
	}
}

// fail books the spend, then moves the record to its terminal failure state.
// The order matters: the message is what a reader polls for, so the cost has
// to already be there when it arrives.
func (r *run) fail(ctx context.Context, userMessage string) {
	r.book(ctx)
	fc, cancel := r.m.terminalCtx()
	defer cancel()
	if err := r.m.store.Fail(fc, r.fixID, userMessage); err != nil && !errors.Is(err, ErrRecordNotFound) {
		r.log.ErrorContext(ctx, "could not record fix failure", slog.Any("error", err))
	}
}

// Execute runs one fix attempt end to end.
//
// userID is not recorded. The source did not record it either, and inventing
// the obligation here would be a new requirement introduced in a comment --
// see [modules.Module].
func (m *Module) Execute(ctx context.Context, userID string, params map[string]any) (*modules.Result, error) {
	_ = userID
	if err := m.Validate(params); err != nil {
		return nil, err
	}
	req, err := m.readRequest(params)
	if err != nil {
		return nil, err
	}
	r := &run{m: m, log: m.log.With(slog.String("fixId", req.fixID)), fixID: req.fixID}

	scan, err := m.scans.Scan(ctx, req.scanID)
	switch {
	case errors.Is(err, ErrRecordNotFound):
		r.fail(ctx, "The scan this finding came from no longer exists")
		return nil, fmt.Errorf("%s: scan %s not found", ModuleID, req.scanID)
	case err != nil:
		r.log.ErrorContext(ctx, "could not read the scan", slog.Any("error", err))
		r.fail(ctx, "Failed to read the scan this finding came from")
		return nil, err
	case scan == nil:
		r.fail(ctx, "The scan this finding came from no longer exists")
		return nil, fmt.Errorf("%s: scan reader returned no scan and no error", ModuleID)
	case !scan.Complete:
		r.fail(ctx, "The scan this finding came from has not completed")
		return nil, fmt.Errorf("%s: scan %s is not complete", ModuleID, req.scanID)
	}

	// The scan must be about the repository this invocation names. Checked
	// here, at the point of use, rather than where the scan was created:
	// the redirect happens afterwards, by invoking this module with a
	// different owner and repository and the same scan identifier.
	//
	// The comparison is exact. Hosting platforms fold case in ways this
	// package does not know, and guessing a folding rule is a widening path on
	// an authorisation check -- so a case difference is refused with a message
	// a person can act on, rather than admitted by a rule nobody verified.
	// Installation is deliberately NOT compared: a public scan legitimately
	// has none, and a fix for it legitimately needs one.
	if err := scanBinding(scan, req.at); err != nil {
		r.log.WarnContext(ctx, "refused a scan bound to another repository",
			slog.String("scanId", req.scanID))
		r.fail(ctx, err.Error())
		return nil, fmt.Errorf("%s: %w", ModuleID, err)
	}
	if req.index < 0 || int(req.index) >= len(scan.Findings) {
		msg := fmt.Sprintf("Finding %d is out of range; the scan reported %d", req.index, len(scan.Findings))
		r.fail(ctx, msg)
		return nil, fmt.Errorf("%s: %s", ModuleID, msg)
	}
	finding := scan.Findings[req.index].Sanitise()

	// The fix runs against the revision the scan ran against, so the agent
	// validates the finding on the tree it was found in. A fix reasoned
	// against a later tree is a fix for a different repository.
	at := req.at
	at.Ref = scan.Ref

	if gone, err := m.markRunning(ctx, r, req.fixID); err != nil {
		return nil, err
	} else if gone != nil {
		return gone, nil
	}

	modules.ReportProgress(ctx, 15, "Downloading repository snapshot")
	snapshot, err := m.source.Fetch(ctx, at, m.maxSourceBytes)
	if err != nil {
		r.log.ErrorContext(ctx, "could not fetch repository snapshot", slog.Any("error", err))
		r.fail(ctx, m.fetchMessage(err))
		return nil, err
	}
	// The resolved commit is what the whole of the rest of this run is
	// computed against, and what the push refuses to write over if the branch
	// has moved since. A snapshot that cannot name it is refused here rather
	// than discovered at the last step.
	switch {
	case snapshot == nil:
		r.fail(ctx, "Failed to download the repository snapshot")
		return nil, fmt.Errorf("%s: source fetcher returned no snapshot and no error", ModuleID)
	case snapshot.Tree == nil:
		r.fail(ctx, "Failed to download the repository snapshot")
		return nil, fmt.Errorf("%s: source fetcher returned a snapshot with no contents", ModuleID)
	case snapshot.Commit == "":
		r.fail(ctx, "Failed to download the repository snapshot")
		return nil, fmt.Errorf("%s: source fetcher returned a snapshot that names no revision", ModuleID)
	}
	tree := snapshot.Tree

	fixReq := Request{Tree: tree, Owner: at.Owner, Repo: at.Repo, Ref: at.Ref, Finding: finding}

	modules.ReportProgress(ctx, 25, "Validating finding")
	m.markStatus(ctx, r, StatusValidating)
	verdict, err := m.fixer.Validate(ctx, fixReq)
	if err != nil {
		r.log.ErrorContext(ctx, "could not validate the finding", slog.Any("error", err))
		r.fail(ctx, "The agent failed to validate the finding")
		return nil, err
	}
	if verdict == nil {
		r.fail(ctx, "The agent failed to validate the finding")
		return nil, fmt.Errorf("%s: fixer returned no verdict and no error", ModuleID)
	}
	r.spend(verdict.Cost)
	m.recordVerdict(ctx, r, *verdict)

	if !verdict.Verdict.Opens() {
		// Terminal, and not a failure: the agent looked and said no.
		r.book(ctx)
		fc, cancel := m.terminalCtx()
		defer cancel()
		if err := m.store.FinalizeRejected(fc, req.fixID); err != nil && !errors.Is(err, ErrRecordNotFound) {
			r.log.ErrorContext(ctx, "could not finalise the rejected finding", slog.Any("error", err))
		}
		modules.ReportProgress(ctx, 100, fmt.Sprintf("Verdict: %s. No pull request opened.", verdict.Verdict))
		return &modules.Result{
			Success: true,
			Message: fmt.Sprintf("Validation complete: %s. No pull request opened.", verdict.Verdict),
			Data:    map[string]any{"fixId": req.fixID, "verdict": string(verdict.Verdict)},
		}, nil
	}

	modules.ReportProgress(ctx, 50, "Drafting patch")
	m.markStatus(ctx, r, StatusPatching)
	patch, err := m.fixer.Propose(ctx, fixReq)
	if err != nil {
		var declined *NoPatchError
		if errors.As(err, &declined) {
			r.spend(declined.Cost)
			r.fail(ctx, formatExplanation(declined.Explanation))
			return nil, err
		}
		r.log.ErrorContext(ctx, "could not draft a patch", slog.Any("error", err))
		r.fail(ctx, "The agent failed to draft a patch for this finding")
		return nil, err
	}
	if patch == nil {
		r.fail(ctx, "The agent failed to draft a patch for this finding")
		return nil, fmt.Errorf("%s: fixer returned no patch and no error", ModuleID)
	}
	r.spend(patch.Cost)

	// Every bound is checked here, before the first write. After a blob has
	// been created there is no decision left to make.
	files, lines, err := EnforceLimits(patch.Files, finding.Category, tree, m.limits)
	if err != nil {
		r.fail(ctx, err.Error())
		return nil, fmt.Errorf("%s: %w", ModuleID, err)
	}
	if len(files) == 0 {
		r.fail(ctx, "The agent proposed no file changes, so there is nothing to commit")
		return nil, fmt.Errorf("%s: the patch is empty", ModuleID)
	}
	encoded, err := json.Marshal(files)
	if err != nil {
		r.log.ErrorContext(ctx, "could not encode the patch", slog.Any("error", err))
		r.fail(ctx, "Failed to record the proposed patch")
		return nil, err
	}
	// The encoded form is what is stored, so it is what the storage ceiling
	// applies to. Summing the raw contents, as the source did, under-counts by
	// whatever escaping costs -- which is unbounded for content that is mostly
	// quotes or control characters.
	if len(encoded) > m.limits.MaxEncodedPatchBytes {
		msg := fmt.Sprintf("The encoded patch is %d bytes; the limit is %d", len(encoded), m.limits.MaxEncodedPatchBytes)
		r.fail(ctx, msg)
		return nil, fmt.Errorf("%s: %s", ModuleID, msg)
	}

	// Record the proposal before pushing, so a failure on the far side still
	// leaves something a person can read.
	{
		pc, cancel := m.terminalCtx()
		if err := m.store.RecordPatch(pc, req.fixID, files, patch.Summary, lines); err != nil && !errors.Is(err, ErrRecordNotFound) {
			r.log.ErrorContext(ctx, "could not record the proposed patch", slog.Any("error", err))
		}
		cancel()
	}

	modules.ReportProgress(ctx, 75, "Pushing branch and opening pull request")
	m.markStatus(ctx, r, StatusPushing)
	outcome, err := m.push(ctx, pushRequest{
		At:       at,
		Tree:     tree,
		Snapshot: snapshot.Commit,
		Files:    files,
		Patch:    patch,
		Finding:  finding,
		Verdict:  verdict,
		ScanID:   req.scanID,
		FixID:    req.fixID,
		Index:    req.index,
	})
	if err != nil {
		// The upstream error can carry a response body, a branch name and
		// authorisation hints, so only the one cause this module can name goes
		// to the requester. Everything else says where to look.
		r.log.ErrorContext(ctx, "could not push the fix", slog.Any("error", err))
		switch {
		case errors.Is(err, ErrBaseNotBranch):
			r.fail(ctx, "A fix pull request needs a branch to target; this scan ran against a tag or a commit. Re-run the scan against a branch.")
		case errors.Is(err, ErrBaseMoved):
			r.fail(ctx, "The branch moved while this fix was being prepared, so the patch was computed against contents that are no longer current. Nothing was written; run the fix again.")
		default:
			r.fail(ctx, "Failed to push the patch; see the runner logs")
		}
		return nil, err
	}

	// Book before the terminal write, so a reader that sees the pull request
	// sees the cost in the same read.
	r.book(ctx)
	{
		cc, cancel := m.terminalCtx()
		defer cancel()
		if err := m.store.Complete(cc, req.fixID, *outcome); err != nil {
			if errors.Is(err, ErrRecordNotFound) {
				r.log.InfoContext(ctx, "record deleted after the pull request was opened",
					slog.String("pullRequest", outcome.PullRequestURL))
				return &modules.Result{Success: true, Message: "Pull request opened, but the record was deleted before it could be stored"}, nil
			}
			// The pull request exists whatever this record says, so the record
			// is moved to a terminal state here rather than left running, and
			// the failure names the pull request so it is not lost.
			r.log.ErrorContext(ctx, "could not record the pull request",
				slog.String("pullRequest", outcome.PullRequestURL), slog.Any("error", err))
			r.booked = true // already written above; do not double-count
			r.fail(ctx, "The pull request was opened but could not be recorded; see the runner logs")
			return nil, fmt.Errorf("%s: record pull request: %w", ModuleID, err)
		}
	}

	modules.ReportProgress(ctx, 100, fmt.Sprintf("Draft pull request #%d opened", outcome.PullRequestNumber))
	return &modules.Result{
		Success: true,
		Message: fmt.Sprintf("Opened draft pull request #%d on %s/%s", outcome.PullRequestNumber, at.Owner, at.Repo),
		Data: map[string]any{
			"fixId":     req.fixID,
			"scanId":    req.scanID,
			"verdict":   string(verdict.Verdict),
			"branch":    outcome.Branch,
			"commitSha": outcome.CommitSHA,
			"prNumber":  outcome.PullRequestNumber,
			"prUrl":     outcome.PullRequestURL,
		},
	}, nil
}

func (m *Module) markRunning(ctx context.Context, r *run, fixID string) (*modules.Result, error) {
	modules.ReportProgress(ctx, 5, "Starting fix")
	mc, cancel := m.terminalCtx()
	defer cancel()
	err := m.store.MarkRunning(mc, fixID)
	switch {
	case err == nil:
		return nil, nil
	case errors.Is(err, ErrRecordNotFound):
		r.log.InfoContext(ctx, "record deleted before the run started")
		return &modules.Result{Success: true, Message: "Fix cancelled: the record was deleted before it started"}, nil
	default:
		r.log.WarnContext(ctx, "could not mark the fix running", slog.Any("error", err))
		return nil, nil
	}
}

func (m *Module) markStatus(ctx context.Context, r *run, status Status) {
	sc, cancel := m.terminalCtx()
	defer cancel()
	if err := m.store.MarkStatus(sc, r.fixID, status); err != nil && !errors.Is(err, ErrRecordNotFound) {
		r.log.WarnContext(ctx, "could not record status", slog.String("status", string(status)), slog.Any("error", err))
	}
}

func (m *Module) recordVerdict(ctx context.Context, r *run, v VerdictResult) {
	vc, cancel := m.terminalCtx()
	defer cancel()
	if err := m.store.RecordVerdict(vc, r.fixID, v); err != nil && !errors.Is(err, ErrRecordNotFound) {
		r.log.ErrorContext(ctx, "could not record the verdict", slog.Any("error", err))
	}
}

// terminalCtx returns a fresh context for a write that must land, for the same
// reason as modules/review's.
func (m *Module) terminalCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), m.limits.TerminalWriteTimeout)
}

func (m *Module) fetchMessage(err error) string {
	switch {
	case errors.Is(err, review.ErrSourceNotFound):
		return "Repository or ref not found"
	case errors.Is(err, review.ErrSourceTooLarge):
		return fmt.Sprintf("Repository snapshot exceeds the %d MiB cap", m.maxSourceBytes>>20)
	case errors.Is(err, review.ErrSourceForbidden):
		return "The source host denied the download; the installation may lack access to this repository"
	default:
		return "Failed to download the repository snapshot"
	}
}

// ErrScanNotBound reports that a scan does not name the repository this
// invocation is for, or names a different one.
var ErrScanNotBound = errors.New("fix: the scan is not bound to this repository")

// scanBinding refuses a scan that is not about the repository being fixed.
//
// An empty owner or repository on the scan is refused rather than treated as
// "any", which is the direction an absent field must fail in when it is what
// an authorisation check reads.
func scanBinding(scan *Scan, at Coordinates) error {
	switch {
	case scan.Owner == "" || scan.Repo == "":
		return fmt.Errorf("%w: the scan does not record which repository it was produced against",
			ErrScanNotBound)
	case scan.Owner != at.Owner || scan.Repo != at.Repo:
		return fmt.Errorf("%w: it was produced against %s/%s and this request is for %s/%s",
			ErrScanNotBound, scan.Owner, scan.Repo, at.Owner, at.Repo)
	default:
		return nil
	}
}

type request struct {
	fixID  string
	scanID string
	index  int64
	at     Coordinates
}

func (m *Module) readRequest(params map[string]any) (request, error) {
	fixID, ok := review.StringParam(params, "fixId")
	if !ok {
		return request{}, fmt.Errorf("fixId is required")
	}
	scanID, ok := review.StringParam(params, "scanId")
	if !ok {
		return request{}, fmt.Errorf("scanId is required")
	}
	index, _ := review.NonNegativeIntParam(params, "findingIndex")
	owner, _ := params["owner"].(string)
	repo, _ := params["repo"].(string)
	installationID, _ := review.PositiveIntParam(params, "installationId")
	return request{
		fixID:  fixID,
		scanID: scanID,
		index:  index,
		at:     Coordinates{Owner: owner, Repo: repo, InstallationID: installationID},
	}, nil
}

// Validate reports whether params are acceptable, without executing.
func (m *Module) Validate(params map[string]any) error {
	if err := modules.ValidateDeclaredParams(m.Schema(), params); err != nil {
		return err
	}
	for _, key := range []string{"fixId", "scanId"} {
		v, ok := review.StringParam(params, key)
		if !ok {
			return fmt.Errorf("%s is required", key)
		}
		if len(v) > maxRecordIDLen || !recordIDRE.MatchString(v) {
			return fmt.Errorf("%s must be alphanumerics, hyphens and underscores, start with an alphanumeric, and be at most %d characters", key, maxRecordIDLen)
		}
	}
	if _, ok := review.NonNegativeIntParam(params, "findingIndex"); !ok {
		return fmt.Errorf("findingIndex is required and must be a non-negative integer")
	}
	// There is one mode, and it is still a declared parameter so that a caller
	// sending the review module's parameter map gets an explanation rather
	// than a rejection for an undeclared key.
	if mode, ok := params["mode"].(string); ok && mode != "" && mode != string(review.ModeInstallation) {
		return fmt.Errorf("mode must be %q: a fix writes to the repository, which anonymous access cannot do", review.ModeInstallation)
	}
	if _, ok := review.PositiveIntParam(params, "installationId"); !ok {
		return fmt.Errorf("installationId is required and must be a positive integer")
	}
	owner, _ := params["owner"].(string)
	repo, _ := params["repo"].(string)
	return review.ValidateOwnerRepo(owner, repo)
}

// Schema is the module's published parameter contract.
func (m *Module) Schema() *modules.JSONSchema {
	return &modules.JSONSchema{
		Type: "object",
		Properties: map[string]modules.JSONSchemaProperty{
			"fixId": {
				Type:        "string",
				Description: "Identifier of the record to report into. The caller creates it before invoking this module.",
			},
			"scanId": {
				Type:        "string",
				Description: "Identifier of the completed scan the finding comes from.",
			},
			"findingIndex": {
				Type:        "integer",
				Description: "Zero-based index of the finding within the scan's findings.",
				Minimum:     ptr(0),
			},
			"mode": {
				Type:        "string",
				Enum:        []string{string(review.ModeInstallation)},
				Default:     string(review.ModeInstallation),
				Description: "Always installation: opening a pull request needs write access, which anonymous access does not have.",
			},
			"installationId": {
				Type:        "integer",
				Description: "Installation with write access to the repository.",
				Minimum:     ptr(1),
			},
			"owner": {
				Type:        "string",
				Description: "Repository owner.",
			},
			"repo": {
				Type:        "string",
				Description: "Repository name, without the owner.",
			},
		},
		Required: []string{"fixId", "scanId", "findingIndex", "installationId", "owner", "repo"},
	}
}

func ptr[T any](v T) *T { return &v }
