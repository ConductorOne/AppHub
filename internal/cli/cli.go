// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package cli implements user commands over the authenticated HTTP SDK.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/conductorone/apphub/internal/mcpserver"
	sdk "github.com/conductorone/apphub/sdk/go"
)

const help = `Usage: apphub <command>

Server/operator commands:
  serve --config <path>
  worker --config <path>
  providers

Authenticated client commands:
  login --server <origin> [--no-browser] [--json]
  whoami [--json]
  logout [--json]
  apps list [--all] [--limit <n>] [--cursor <cursor>] [--json]
  apps get <id> [--json]
  apps create --file <json> [--idempotency-key <key>] [--json]
  apps update <id> --file <json> --revision <n> [--json]
  apps delete <id> --confirm <name> [--idempotency-key <key>] [--json]
  apps owners list <id> [--json]
  apps owners add <id> (--user <user-id> | --group <group-id>) [--json]
  apps owners remove <id> <owner-key> [--json]
  apps owners search [<query>] [--json]
  deploy <application-id> --revision <n> [--idempotency-key <key>] [--wait] [--timeout <duration>] [--json]
  deployments get <id> [--json]
  deployments resolve-interrupted <id> --worker-stopped --reason <text> [--json]
  mcp stdio

Create makes a draft only. Deploy submits a separate durable operation.
--no-browser prints the normal browser-login URL (usable with SSH forwarding).
Canceling --wait stops observation, not the server-side deployment.
`

type recovery struct {
	ApplicationID  string `json:"applicationId,omitempty"`
	DeploymentID   string `json:"deploymentId,omitempty"`
	IdempotencyKey string `json:"idempotencyKey,omitempty"`
	Revision       int64  `json:"applicationRevision,omitempty"`
}

type commandResult struct {
	value       any
	err         error
	recovery    *recovery
	observation any
	usage       bool
}

// Run executes one invocation. JSON mode emits exactly one JSON value on
// stdout; all prompts, progress, recovery advice, and diagnostics use stderr.
// Stderr diagnostics are best-effort and never replace the operation result or
// its recovery data; failure to write the stdout result is a command failure.
// The composition root supplies a signal-aware context.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	jsonMode := false
	for _, arg := range args {
		if arg == "--json" || arg == "--json=true" {
			jsonMode = true
		}
	}
	if len(args) == 2 && args[0] == "mcp" && args[1] == "stdio" {
		client, err := sdk.FromContext()
		if err == nil {
			err = mcpserver.RunStdio(ctx, client)
		}
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err) // Best-effort diagnostic; the command already failed.
			return 1
		}
		return 0
	}
	if len(args) == 0 || (len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h")) {
		if jsonMode {
			_ = json.NewEncoder(stdout).Encode(map[string]string{"help": help})
		} else {
			_, _ = io.WriteString(stdout, help)
		}
		return 0
	}
	result := dispatch(ctx, args, stderr)
	if result.err != nil {
		_, _ = fmt.Fprintln(stderr, result.err)
		if result.recovery != nil {
			r := result.recovery
			if r.ApplicationID != "" {
				_, _ = fmt.Fprintf(stderr, "Application: %s (revision %d)\n", r.ApplicationID, r.Revision)
			}
			if r.DeploymentID != "" {
				_, _ = fmt.Fprintf(stderr, "Deployment remains observable: apphub deployments get %s\n", r.DeploymentID)
			}
			var outcome *sdk.DeploymentOutcomeError
			var uncertain *sdk.UncertainError
			switch {
			case errors.As(result.err, &outcome):
				if outcome.Deployment.State == "interrupted" {
					_, _ = fmt.Fprintln(stderr, "Operator resolution is required: stop the old worker and build container, then resolve the interrupted operation before submitting a new deployment.")
				} else {
					_, _ = fmt.Fprintln(stderr, "This attempt failed. Inspect or update the application, then submit a new explicit deployment with its current revision and a new idempotency key; reusing this attempt's key only returns the same failed operation.")
				}
			case r.IdempotencyKey != "" && errors.As(result.err, &uncertain):
				_, _ = fmt.Fprintf(stderr, "Retry the identical request with --idempotency-key %s; do not generate a new key for an uncertain outcome.\n", r.IdempotencyKey)
			}
		}
	}
	value := result.value
	if value == nil && result.err != nil && jsonMode {
		code := "client_error"
		if result.usage {
			code = "usage"
		}
		envelope := sdk.ErrorResponse{Error: sdk.Error{Code: code, Message: result.err.Error()}}
		var apiErr *sdk.APIError
		if errors.As(result.err, &apiErr) {
			envelope = apiErr.Response
		}
		value = struct {
			sdk.ErrorResponse
			Recovery   *recovery `json:"recovery,omitempty"`
			Deployment any       `json:"deployment,omitempty"`
		}{envelope, result.recovery, result.observation}
	}
	if value != nil {
		encoder := json.NewEncoder(stdout)
		if !jsonMode {
			encoder.SetIndent("", "  ")
		}
		if err := encoder.Encode(value); err != nil {
			_, _ = fmt.Fprintln(stderr, "write command result:", err)
			return 1
		}
	}
	if result.err != nil {
		if result.usage {
			return 2
		}
		return 1
	}
	return 0
}

func flags(name string) (*flag.FlagSet, *bool) {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f, f.Bool("json", false, "emit one JSON value")
}

func parse(f *flag.FlagSet, args []string) error {
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", f.Arg(0))
	}
	return nil
}

func usage(err error) commandResult { return commandResult{err: err, usage: true} }

func dispatch(ctx context.Context, args []string, stderr io.Writer) commandResult {
	switch args[0] {
	case "login":
		f, _ := flags("login")
		server := f.String("server", "", "AppHub origin")
		noBrowser := f.Bool("no-browser", false, "print browser URL without opening")
		if err := parse(f, args[1:]); err != nil {
			return usage(err)
		}
		if *server == "" {
			return usage(errors.New("login requires --server <origin>"))
		}
		client, err := sdk.Login(ctx, *server, *noBrowser, stderr)
		if err != nil {
			return commandResult{err: err}
		}
		return commandResult{value: map[string]any{"server": client.Server, "authenticated": true}}
	case "whoami", "logout":
		f, _ := flags(args[0])
		if err := parse(f, args[1:]); err != nil {
			return usage(err)
		}
		client, err := sdk.FromContext()
		if err != nil {
			return commandResult{err: err}
		}
		if args[0] == "logout" {
			if err := client.Logout(ctx); err != nil {
				return commandResult{err: err}
			}
			return commandResult{value: map[string]bool{"loggedOut": true}}
		}
		result, err := client.WhoAmI(ctx)
		if err != nil {
			return commandResult{err: err}
		}
		return commandResult{value: result}
	case "apps":
		return apps(ctx, args[1:], stderr)
	case "deploy":
		return deploy(ctx, args[1:], stderr)
	case "deployments":
		return deployments(ctx, args[1:])
	default:
		return usage(fmt.Errorf("unknown command %q; run apphub help", args[0]))
	}
}

func apps(ctx context.Context, args []string, stderr io.Writer) commandResult {
	if len(args) == 0 {
		return usage(errors.New("apps requires list, get, create, update, delete, or owners"))
	}
	switch args[0] {
	case "list":
		f, _ := flags("apps list")
		all := f.Bool("all", false, "admin: list all applications")
		limit := f.Int("limit", 50, "page size (1-100)")
		cursor := f.String("cursor", "", "opaque continuation")
		if err := parse(f, args[1:]); err != nil {
			return usage(err)
		}
		if *limit < 1 || *limit > 100 {
			return usage(errors.New("limit must be between 1 and 100"))
		}
		client, err := sdk.FromContext()
		if err != nil {
			return commandResult{err: err}
		}
		result, err := client.ListApplications(ctx, sdk.ListApplicationsParams{All: all, Limit: limit, Cursor: cursor})
		if err != nil {
			return commandResult{err: err}
		}
		return commandResult{value: result}
	case "get":
		if len(args) < 2 || strings.HasPrefix(args[1], "-") {
			return usage(errors.New("apps get requires an application ID"))
		}
		f, _ := flags("apps get")
		if err := parse(f, args[2:]); err != nil {
			return usage(err)
		}
		client, err := sdk.FromContext()
		if err != nil {
			return commandResult{err: err}
		}
		result, err := client.GetApplication(ctx, args[1])
		if err != nil {
			return commandResult{err: err}
		}
		return commandResult{value: result}
	case "delete":
		return deleteApp(ctx, args[1:], stderr)
	case "owners":
		return owners(ctx, args[1:])
	case "create", "update":
		f, _ := flags("apps " + args[0])
		file := f.String("file", "", "application specification JSON file")
		var revision *int64
		var key *string
		rest := args[1:]
		id := ""
		if args[0] == "update" {
			if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
				return usage(errors.New("apps update requires an application ID"))
			}
			id, rest = rest[0], rest[1:]
			revision = f.Int64("revision", 0, "current application revision")
		} else {
			key = f.String("idempotency-key", "", "reuse for retrying identical creation")
		}
		if err := parse(f, rest); err != nil {
			return usage(err)
		}
		if *file == "" {
			return usage(errors.New("--file is required"))
		}
		if revision != nil && *revision < 1 {
			return usage(errors.New("--revision must be positive"))
		}
		input, err := applicationFile(*file)
		if err != nil {
			return usage(err)
		}
		client, err := sdk.FromContext()
		if err != nil {
			return commandResult{err: err}
		}
		if revision != nil {
			result, err := client.UpdateApplication(ctx, id, *revision, input)
			if err != nil {
				return commandResult{err: err, recovery: &recovery{ApplicationID: id, Revision: *revision}}
			}
			return commandResult{value: result}
		}
		if *key == "" {
			*key = sdk.NewIdempotencyKey()
		}
		_, _ = fmt.Fprintf(stderr, "Creation idempotency key: %s\n", *key)
		result, err := client.CreateApplication(ctx, input, *key)
		if err != nil {
			return commandResult{err: err, recovery: &recovery{IdempotencyKey: *key}}
		}
		_, _ = fmt.Fprintf(stderr, "Draft created. Deploy separately: apphub deploy %s --revision %d\n", result.Id, result.Revision)
		return commandResult{value: result}
	default:
		return usage(fmt.Errorf("unknown apps command %q", args[0]))
	}
}

// deleteApp deletes an application and every resource it owns. --confirm must
// repeat the application's name, which the server checks too.
func deleteApp(ctx context.Context, args []string, stderr io.Writer) commandResult {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usage(errors.New("apps delete requires an application ID"))
	}
	f, _ := flags("apps delete")
	confirm := f.String("confirm", "", "the application's exact name; its data is destroyed without a snapshot")
	key := f.String("idempotency-key", "", "reuse for retrying the identical request; use a new one to retry a failed teardown")
	if err := parse(f, args[1:]); err != nil {
		return usage(err)
	}
	if *confirm == "" {
		return usage(errors.New("--confirm <application name> is required"))
	}
	client, err := sdk.FromContext()
	if err != nil {
		return commandResult{err: err}
	}
	if *key == "" {
		*key = sdk.NewIdempotencyKey()
	}
	recoveryInfo := &recovery{ApplicationID: args[0], IdempotencyKey: *key}
	_, _ = fmt.Fprintf(stderr, "Deletion idempotency key: %s\n", *key)
	accepted, err := client.DeleteApplication(ctx, args[0], sdk.DeleteApplicationInput{ConfirmName: *confirm}, *key)
	if err != nil {
		return commandResult{err: err, recovery: recoveryInfo}
	}
	if accepted == nil {
		_, _ = fmt.Fprintln(stderr, "The application had never been deployed and was deleted.")
		return commandResult{value: map[string]bool{"deleted": true}}
	}
	recoveryInfo.DeploymentID = accepted.DeploymentId.String()
	_, _ = fmt.Fprintf(stderr, "Teardown queued: observe it with apphub deployments get %s; it reports not found once the application is gone.\n", recoveryInfo.DeploymentID)
	return commandResult{value: accepted}
}

// owners lists, adds, removes and searches for application owners.
func owners(ctx context.Context, args []string) commandResult {
	if len(args) == 0 {
		return usage(errors.New("apps owners requires list, add, remove, or search"))
	}
	command, rest := args[0], args[1:]
	if command == "search" {
		return searchOwners(ctx, rest)
	}
	if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
		return usage(fmt.Errorf("apps owners %s requires an application ID", command))
	}
	id, rest := rest[0], rest[1:]
	switch command {
	case "list":
		return ownerCall(rest, "apps owners list", func(client *sdk.Client) (any, error) { return client.ListOwners(ctx, id) })
	case "add":
		return addOwner(ctx, id, rest)
	case "remove":
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			return usage(errors.New("apps owners remove requires an owner key (user:<id> or group:<id>) from apps owners list"))
		}
		key := rest[0]
		return ownerCall(rest[1:], "apps owners remove", func(client *sdk.Client) (any, error) { return client.RemoveOwner(ctx, id, key) })
	default:
		return usage(fmt.Errorf("unknown apps owners command %q", command))
	}
}

func addOwner(ctx context.Context, id string, args []string) commandResult {
	f, _ := flags("apps owners add")
	user := f.String("user", "", "user ID to add, from apps owners search")
	group := f.String("group", "", "directory group ID to add; everyone in it becomes an owner")
	if err := parse(f, args); err != nil {
		return usage(err)
	}
	if (*user == "") == (*group == "") {
		return usage(errors.New("apps owners add requires exactly one of --user or --group"))
	}
	input := sdk.OwnerInput{Kind: sdk.OwnerKindUser, Id: *user}
	if *group != "" {
		input = sdk.OwnerInput{Kind: sdk.OwnerKindGroup, Id: *group}
	}
	return ownerCall(nil, "apps owners add", func(client *sdk.Client) (any, error) { return client.AddOwner(ctx, id, input) })
}

func searchOwners(ctx context.Context, args []string) commandResult {
	query := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		query, args = args[0], args[1:]
	}
	return ownerCall(args, "apps owners search", func(client *sdk.Client) (any, error) { return client.SearchPrincipals(ctx, query) })
}

// ownerCall parses the remaining flags and runs one authenticated call.
func ownerCall(args []string, name string, call func(*sdk.Client) (any, error)) commandResult {
	f, _ := flags(name)
	if err := parse(f, args); err != nil {
		return usage(err)
	}
	client, err := sdk.FromContext()
	if err != nil {
		return commandResult{err: err}
	}
	value, err := call(client)
	if err != nil {
		return commandResult{err: err}
	}
	return commandResult{value: value}
}

func applicationFile(path string) (sdk.ApplicationInput, error) {
	var input sdk.ApplicationInput
	f, err := os.Open(path) // #nosec G304 -- The local CLI user explicitly selects --file; reading that user's chosen specification path is the intended operation, not a server-side path boundary.
	if err != nil {
		return input, fmt.Errorf("open application file: %w", err)
	}
	defer func() { _ = f.Close() }() // Read-only input; read errors determine validity.
	b, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return input, err
	}
	if len(b) > 64<<10 {
		return input, errors.New("application specification exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return input, fmt.Errorf("invalid application JSON: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return input, errors.New("application file must contain exactly one JSON object")
	}
	return input, nil
}

func deploy(ctx context.Context, args []string, stderr io.Writer) commandResult {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usage(errors.New("deploy requires an application ID"))
	}
	f, _ := flags("deploy")
	revision := f.Int64("revision", 0, "application revision to deploy")
	key := f.String("idempotency-key", "", "reuse for retrying identical submission")
	wait := f.Bool("wait", false, "observe durable operation until terminal")
	timeout := f.Duration("timeout", 30*time.Minute, "maximum observation duration (does not cancel deployment)")
	if err := parse(f, args[1:]); err != nil {
		return usage(err)
	}
	if *revision < 1 {
		return usage(errors.New("--revision must be positive"))
	}
	if *timeout <= 0 {
		return usage(errors.New("--timeout must be positive"))
	}
	client, err := sdk.FromContext()
	if err != nil {
		return commandResult{err: err}
	}
	if *key == "" {
		*key = sdk.NewIdempotencyKey()
	}
	recoveryInfo := &recovery{ApplicationID: args[0], Revision: *revision, IdempotencyKey: *key}
	_, _ = fmt.Fprintf(stderr, "Deployment idempotency key: %s\n", *key)
	accepted, err := client.SubmitDeployment(ctx, args[0], sdk.SubmitDeploymentInput{ApplicationRevision: *revision}, *key)
	if err != nil {
		return commandResult{err: err, recovery: recoveryInfo}
	}
	recoveryInfo.DeploymentID = accepted.DeploymentId.String()
	_, _ = fmt.Fprintf(stderr, "Deployment: %s\n", recoveryInfo.DeploymentID)
	if !*wait {
		return commandResult{value: accepted}
	}
	observeCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	view, err := client.WaitDeployment(observeCtx, recoveryInfo.DeploymentID, func(view sdk.DeploymentView) {
		step := ""
		if view.Step != nil {
			step = *view.Step
		}
		_, _ = fmt.Fprintf(stderr, "%s %s %s\n", view.State, step, view.Message)
	})
	var outcome *sdk.DeploymentOutcomeError
	if errors.As(err, &outcome) {
		return commandResult{value: view, err: err, recovery: recoveryInfo}
	}
	if err != nil {
		return commandResult{err: fmt.Errorf("stopped observing deployment (execution is not canceled): %w", err), recovery: recoveryInfo, observation: view}
	}
	if view.Execution == "scheduled" {
		_, _ = fmt.Fprintln(stderr, "Schedule installed; this does not assert that a scheduled execution succeeded.")
	}
	return commandResult{value: view}
}

func deployments(ctx context.Context, args []string) commandResult {
	if len(args) < 2 || strings.HasPrefix(args[1], "-") {
		return usage(errors.New("deployments requires get <id> or resolve-interrupted <id>"))
	}
	f, _ := flags("deployments " + args[0])
	var stopped *bool
	var reason *string
	if args[0] == "resolve-interrupted" {
		stopped = f.Bool("worker-stopped", false, "confirm old worker and build container stopped")
		reason = f.String("reason", "", "operator explanation")
	} else if args[0] != "get" {
		return usage(fmt.Errorf("unknown deployments command %q", args[0]))
	}
	if err := parse(f, args[2:]); err != nil {
		return usage(err)
	}
	if stopped != nil && (!*stopped || strings.TrimSpace(*reason) == "") {
		return usage(errors.New("resolution requires --worker-stopped and a nonempty --reason"))
	}
	client, err := sdk.FromContext()
	if err != nil {
		return commandResult{err: err}
	}
	var result *sdk.DeploymentView
	if stopped == nil {
		result, err = client.GetDeployment(ctx, args[1])
	} else {
		result, err = client.ResolveInterruptedDeployment(ctx, args[1], sdk.ResolveInterruptedInput{WorkerStopped: sdk.ResolveInterruptedInputWorkerStopped(*stopped), Reason: *reason})
	}
	if err != nil {
		return commandResult{err: err, recovery: &recovery{DeploymentID: args[1]}}
	}
	return commandResult{value: result}
}
