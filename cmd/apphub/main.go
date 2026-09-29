// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command apphub assembles the application control plane and its clients.
//
// The providers subcommand reports the optional credential-provider registry.
// It remains the sole composition root allowed to import credentials/c1; no
// library depends on ConductorOne. Partial optional-provider configuration is
// an error, never a silent fallback to an unconfigured provider.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/c1"
	"github.com/conductorone/apphub/credentials/datadog"
	"github.com/conductorone/apphub/credentials/github"
	"github.com/conductorone/apphub/internal/cli"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

// run is main with its environment injected, so a test can exercise the real
// wiring without a process-global environment.
//
// getenv rather than os.Getenv, and io.Writers rather than os.Stdout, for the
// same reason every dependency in credentials/c1 is an interface: a composition
// root whose only entry point is func main() is a composition root nothing can
// test.
func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		if _, err := fmt.Fprintln(stdout, "Usage: apphub <command>\n\nCommands:\n  serve       Run the authenticated application API\n  worker      Run the isolated deployment dispatcher\n  providers   Report configured credential providers\n  login       Sign in to an AppHub server\n  whoami      Show the current identity\n  logout      Revoke this CLI session\n  apps        List, create, inspect or update applications\n  deploy      Submit and optionally observe a deployment\n  deployments Inspect deployments or resolve an interruption\n  mcp stdio   Serve MCP through the authenticated CLI context"); err != nil {
			return 1
		}
		return 0
	}
	switch args[0] {
	case "serve", "worker":
		return hostCommand(args[0], args[1:], stderr, getenv)
	case "providers":
		if len(args) != 1 {
			_, _ = fmt.Fprintln(stderr, "apphub: providers takes no arguments")
			return 2
		}
		return providers(stdout, stderr, getenv)
	default:
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		return cli.Run(ctx, args, stdout, stderr)
	}
}

func providers(stdout, stderr io.Writer, getenv func(string) string) int {
	reg := credentials.NewProviderRegistry()

	// The providers that need no configuration to exist. Each takes its
	// operator credentials per call, in credentials.Metadata, so registering one
	// commits a deployment to nothing.
	for _, p := range []credentials.CredentialProvider{
		datadog.NewProvider(),
		github.NewProvider(),
	} {
		if err := reg.Register(p); err != nil {
			_, _ = fmt.Fprintf(stderr, "apphub: registering a provider failed: %v\n", err)
			return 1
		}
	}

	conductorOne, err := registerConductorOne(reg, getenv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "apphub: %v\n", err)
		return 1
	}

	report(stdout, reg, conductorOne)
	return 0
}

// registerConductorOne wires the ConductorOne provider if the deployment
// configured one, and reports whether it did.
//
// ErrNotConfigured is not an error here and is the only error treated that way:
// it is how a deployment says it does not use ConductorOne. Everything else stops
// startup.
func registerConductorOne(reg *credentials.ProviderRegistry, getenv func(string) string) (bool, error) {
	cfg, err := c1.ConfigFromEnv(getenv)
	switch {
	case errors.Is(err, c1.ErrNotConfigured):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("conductorone configuration is incomplete: %w", err)
	}

	if err := c1.Register(reg, cfg, c1.Deps{Secrets: fileSecrets{getenv: getenv}}); err != nil {
		if errors.Is(err, c1.ErrNotConfigured) {
			// Register re-checks Enabled, so this is unreachable via
			// ConfigFromEnv, which already refused an empty configuration. Handled
			// rather than assumed away: the two functions are separately
			// documented to refuse an empty configuration, and treating this as a
			// startup failure would turn "ConductorOne is off" into a crash if
			// either ever changed.
			return false, nil
		}
		return false, fmt.Errorf("registering the conductorone provider failed: %w", err)
	}
	return true, nil
}

// report prints the registry.
//
// The output is one stable line per fact, sorted by provider ID, so that it can
// be asserted on rather than eyeballed. It names ids, names and capabilities and
// nothing else: no tenant URL, no secret locator, no environment values.
func report(w io.Writer, reg *credentials.ProviderRegistry, conductorOne bool) {
	providers := reg.List()
	sort.Slice(providers, func(i, j int) bool { return providers[i].ID() < providers[j].ID() })

	_, _ = fmt.Fprintf(w, "apphub: credential providers registered: %d\n", len(providers))
	for _, p := range providers {
		caps := credentials.CapabilitiesOf(p)
		_, _ = fmt.Fprintf(w, "provider: id=%s name=%s dynamic=%t static=%t revoke=%t status=%t recover=%t\n",
			p.ID(), p.Name(), caps.Dynamic, caps.Static, caps.Revoke, caps.Status, caps.RecoverCreate)
	}
	if conductorOne {
		_, _ = fmt.Fprintln(w, "conductorone: configured")
		return
	}
	_, _ = fmt.Fprintln(w, "conductorone: not configured")
}

// fileSecrets resolves a credentials.SecretRef from the local process: an
// absolute file path, or an environment variable ECS injected from Parameter
// Store.
//
// This is the one resolver the shipped binary offers. A secret mounted into a
// container's filesystem and a secret injected into the process environment
// are the two ways ECS actually presents one. An adopter whose secrets live
// in a cloud secret manager the task reads at use time implements
// c1.SecretResolver themselves and wires it here; that is what a composition
// root is for, and it is why c1.Deps takes an interface.
//
// It fails closed in three ways that matter. A reference naming a store this
// binary does not implement is refused rather than read off the local disk or
// environment, so a reference meant for a parameter store cannot be satisfied
// by a same-named file. A relative path is refused, because a relative path
// resolves against whatever the working directory happens to be at startup.
// And a reference that names both a file and an environment variable is
// refused, because that is two places the material might live and no rule
// for which one wins.
type fileSecrets struct {
	getenv func(string) string
}

// errRefNotAFile means the reference does not name something this resolver reads.
//
// It renders neither the store nor the path. A locator is not material, but it is
// deployment topology, and this binary's stderr is a place an operator's log
// shipper reads.
var errRefNotAFile = errors.New("apphub: the client secret reference does not name an absolute file path or an environment variable in this binary's process-backed secret store")

func (s fileSecrets) lookup(name string) string {
	if s.getenv != nil {
		return s.getenv(name)
	}
	return os.Getenv(name)
}

func (s fileSecrets) Resolve(_ context.Context, ref credentials.SecretRef) (credentials.Secret, error) {
	if ref.Store != "" {
		return credentials.Secret{}, errRefNotAFile
	}
	if ref.EnvVar != "" {
		if ref.Name != "" {
			return credentials.Secret{}, errRefNotAFile
		}
		b := strings.TrimSpace(s.lookup(ref.EnvVar))
		if b == "" {
			return credentials.Secret{}, errSecretEmpty
		}
		return credentials.NewSecret(b), nil
	}
	if !filepath.IsAbs(ref.Name) {
		return credentials.Secret{}, errRefNotAFile
	}
	b, err := os.ReadFile(ref.Name)
	if err != nil {
		// os.ReadFile's error contains the path. The path is the locator, and the
		// refusal above already told the operator what shape is expected.
		return credentials.Secret{}, errSecretUnreadable
	}
	secret := credentials.NewSecret(strings.TrimSpace(string(b)))
	if secret.IsZero() {
		return credentials.Secret{}, errSecretEmpty
	}
	return secret, nil
}

// The two ways reading a mounted secret fails.
var (
	errSecretUnreadable = errors.New("apphub: the file named by the client secret reference could not be read")
	errSecretEmpty      = errors.New("apphub: the file named by the client secret reference was empty")
)
