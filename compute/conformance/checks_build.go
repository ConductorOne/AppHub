// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/conductorone/apphub/compute"
)

// The image-build checks (USOSS-39).
//
// Before this, [compute.ImageBuilder.Build] was driven by no check in the suite
// at all. That is a different thing from a lenient check and wants saying
// plainly: **it was a gate with no input.** There was no tolerant path to
// tighten. And it was not a quiet corner — the port carries the heaviest
// obligation in the whole interface, stated in capitals in compute/image.go
// precisely because it could not be expressed as a method:
//
//	A provider MUST NOT expose ambient platform credentials to the build.
//	Credentials made available to a build MUST be scoped to no more than push
//	access to Destinations and Cache, and MUST be short-lived.
//
// with the reason attached: Dockerfile RUN instructions execute arbitrary
// repository-authored code, so a builder that inherits the platform's own
// credentials hands them to whoever wrote the repository. In the source system
// kaniko unpacks the image into the container it runs in and shares a PID
// namespace with the commands it runs, so a RUN can read the executor's
// environment — which holds the short-lived push credential — and print it.
//
// And [compute.BuildRequest.Logs] documents where that print ends up: the caller
// "keeps a capped tail so a build failure's diagnostic can be persisted onto a
// 400 KB DynamoDB item ... which is a caller policy, not a provider one".
//
// So the interface documents that build output reaches durable storage,
// documents that the provider must not put credentials near the build, and
// checked neither half. Both halves are checked here.
//
// The threat model these checks are written against is a build context authored
// by whoever owns the repository being built, not a cooperative one. The
// reference provider's builder is deliberately adversarial under
// fake.DefectBuildCredentialInLogs and friends, because a cooperative fake is
// what made the equivalent provider-side test in PR #18 useless: it used a
// benign recorder that could not exercise the path, while the provider it tested
// really did put a session token into Logs.

// buildMarker is planted in the build context. Anything a builder echoes from
// the context is repository-authored content, and repository-authored content
// reaching a persisted error is the leak this file is about.
const buildMarker = "conformance-build-context-marker-4d7e9a1f"

// BuildFixture is a build the suite can run more than once: a context directory
// on disk and a destination in a repository the provider hosts.
type BuildFixture struct {
	// ContextDir is a directory containing a Dockerfile and a planted marker.
	ContextDir string
	// Destination is a reference inside a repository this provider hosts.
	Destination compute.ImageRef
	// Repository is the ref of the repository behind Destination.
	Repository compute.Ref

	builder compute.ImageBuilder
}

// Build runs the fixture's build, capturing anything written to Logs.
func (f *BuildFixture) Build(tb TB, e *Env, logs *bytes.Buffer) (*compute.BuildResult, error) {
	tb.Helper()
	req := compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: f.ContextDir},
		Destinations: []compute.ImageRef{f.Destination},
	}
	if logs != nil {
		req.Logs = logs
	}
	return f.builder.Build(e.ctx, req)
}

// buildFixture prepares a build, or returns nil when this provider cannot be
// given one.
//
// A build needs somewhere to push, so it needs [compute.CapImageBuild] *and*
// [compute.CapImageRegistry]. A provider with the first and not the second
// cannot be handed a legal Destination at all, which is a real configuration
// (compute/k8s with BuildKit and no registry) rather than a gap in the suite.
func buildFixture(tb TB, e *Env) *BuildFixture {
	tb.Helper()
	caps := e.Provider.Capabilities()
	if !caps.Has(compute.CapImageBuild) || !caps.Has(compute.CapImageRegistry) {
		return nil
	}
	builder, err := e.Provider.Builder()
	if err != nil {
		fatal(tb, "image-build", "an advertised capability's port can be acquired",
			"the provider advertises %q but Builder() refused: %v", compute.CapImageBuild, err)
	}
	reg, err := e.Provider.Registry()
	if err != nil {
		fatal(tb, "image-build", "an advertised capability's port can be acquired",
			"the provider advertises %q but Registry() refused: %v", compute.CapImageRegistry, err)
	}
	repo, err := reg.EnsureRepository(e.ctx, compute.RepositorySpec{
		Name:   e.Name("build"),
		Labels: map[string]string{"owner": "conformance"},
	})
	if err != nil {
		fatal(tb, "image-build", "a build needs a repository to push to",
			"EnsureRepository failed: %v", err)
	}
	if repo.Prefix == "" {
		fatal(tb, "image-build", "a build needs a repository to push to",
			"EnsureRepository returned an empty Prefix, so there is nothing to push to")
	}
	return &BuildFixture{
		ContextDir:  buildContext(tb),
		Destination: compute.ImageRef(repo.Prefix + ":conformance"),
		Repository:  repo.Ref,
		builder:     builder,
	}
}

// buildContext writes a minimal build context containing the marker, and removes
// it when the check finishes.
//
// [TB] deliberately has no TempDir — the suite is an interface, not a
// *testing.T — so the directory is made here and cleaned up through Cleanup,
// which TB does have.
func buildContext(tb TB) string {
	tb.Helper()
	dir, err := os.MkdirTemp("", "conformance-build-")
	if err != nil {
		tb.Fatalf("conformance: [image-build] creating a build context: %v", err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })

	// The Dockerfile carries the marker in a position a builder that echoes its
	// input will reproduce. This stands in for repository-authored content: on
	// the source system it would be a RUN line printing the executor's
	// environment.
	recipe := "FROM scratch\n# " + buildMarker + "\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(recipe), 0o600); err != nil {
		tb.Fatalf("conformance: [image-build] writing the build context: %v", err)
	}
	return dir
}

func buildChecks(_ *Env) []Check {
	return []Check{
		{
			Name:      "port/image-build/logs-receive-the-builder-output",
			Port:      "image-build",
			Invariant: "a build with a Logs writer writes its progress to it",
			Fn:        checkBuildLogsSomething,
		},
		{
			Name:      "port/image-build/a-build-with-no-destination-is-refused",
			Port:      "image-build",
			Invariant: "a build with no destination is ErrInvalidSpec rather than a build of nothing",
			Fn:        checkBuildNeedsADestination,
		},
		{
			Name:      "security/build-credentials-do-not-appear-in-what-a-build-emits",
			Port:      "image-build",
			Invariant: "credentials made available to a build appear in no log, error or result",
			Fn:        checkBuildCredentialsNotEmitted,
		},
		{
			Name:      "security/build-output-does-not-appear-in-an-error",
			Port:      "image-build",
			Invariant: "a failed build's error carries no builder output",
			Fn:        checkBuildOutputNotInError,
		},
		{
			Name:      "security/build-credentials-do-not-appear-in-image-metadata",
			Port:      "image-build",
			Invariant: "credentials made available to a build appear in no image metadata",
			Fn:        checkBuildCredentialsNotInImageMetadata,
		},
		{
			Name:      "port/image-build/build-cache-default-is-not-forever",
			Port:      "image-build",
			Invariant: `a build cache's default MaxAge, when the caller leaves it zero, is not "forever"`,
			Fn:        checkBuildCacheDefaultIsBounded,
		},
	}
}

// checkBuildLogsSomething is the anti-vacuity assertion the other two security
// checks stand on.
//
// Scanning a log for material proves nothing if the log is empty, and a builder
// that writes nothing to the writer it was handed would pass every such scan
// while also depriving its caller of a build's only progress signal. So this
// runs first and asserts the channel carries something.
func checkBuildLogsSomething(tb TB, e *Env) {
	const inv = "a build with a Logs writer writes its progress to it"
	f := buildFixture(tb, e)
	if f == nil {
		skipBecause(tb, e, inv, buildUnavailable(e))
		return
	}
	var logs bytes.Buffer
	if _, err := f.Build(tb, e, &logs); err != nil {
		fail(tb, "image-build", inv, "a build of a legal context was refused: %v", redact(err))
		return
	}
	if logs.Len() == 0 {
		fail(tb, "image-build", inv, "the build wrote nothing to the Logs writer it was given. "+
			"A build's output stream is its only progress signal — provisioning has a phase to "+
			"poll and a build does not — and a builder that emits nothing also passes every "+
			"check that scans its output for material it should not contain")
	}
}

// checkBuildNeedsADestination pins the documented requirement that at least one
// destination is required. A build with nowhere to push is a build whose output
// is discarded, reported as a success.
func checkBuildNeedsADestination(tb TB, e *Env) {
	const inv = "a build with no destination is ErrInvalidSpec rather than a build of nothing"
	f := buildFixture(tb, e)
	if f == nil {
		skipBecause(tb, e, inv, buildUnavailable(e))
		return
	}
	_, err := f.builder.Build(e.ctx, compute.BuildRequest{
		Source: compute.BuildSource{ContextDir: f.ContextDir},
	})
	switch {
	case err == nil:
		fail(tb, "image-build", inv, "a build with no Destinations reported success; the caller "+
			"has no way to tell that nothing was published, and the next deploy pulls an image "+
			"nobody pushed")
	case !errors.Is(err, compute.ErrInvalidSpec):
		fail(tb, "image-build", inv, "a build with no Destinations was refused with %v, which "+
			"does not match compute.ErrInvalidSpec", redact(err))
	}
}

// checkBuildCredentialsNotEmitted is the check the obligation in
// [compute.ImageBuilder] never had.
//
// It needs the provider to say what material its build is given, because the
// suite cannot know: the whole point of the design is that the credential is
// minted inside the provider and never reaches the caller. That makes it a hook,
// and a nil hook is reported as an unverified invariant rather than passed.
func checkBuildCredentialsNotEmitted(tb TB, e *Env) {
	const inv = "credentials made available to a build appear in no log, error or result"
	f := buildFixture(tb, e)
	if f == nil {
		skipBecause(tb, e, inv, buildUnavailable(e))
		return
	}
	if e.Options.BuildCredentials == nil {
		skip(tb, e, inv, "Options.BuildCredentials, which has to report the material this "+
			"provider makes available to a build — the suite cannot know it, because the "+
			"interface deliberately never shows a minted credential to the caller")
		return
	}
	material, err := e.Options.BuildCredentials(e.ctx, e.Provider)
	if err != nil {
		fatal(tb, "image-build", inv, "Options.BuildCredentials failed: %v", err)
	}
	// A derivation returning nothing passes every check over it. A provider that
	// reports no build material has either nothing to protect — in which case
	// say so through a nil hook — or a hook that does not work.
	if len(material) == 0 {
		fail(tb, "image-build", inv, "Options.BuildCredentials reported no material, so the "+
			"scan below would search a build's output for nothing at all. A provider whose build "+
			"genuinely holds no credential should leave the hook nil, which is reported as "+
			"unverified rather than as a pass")
		return
	}

	// All three channels this check reads, established and scanned by one call
	// over one map. The first version gated only the log while scanning the log,
	// the error and the result, and a reviewer defeated it with a hook that
	// emitted into the log and silently accepted the error channel: the check
	// passed while claiming credentials appear in no log, error or result.
	//
	// Each reader performs a build and returns what its channel carried, so a
	// channel cannot be scanned without first being shown to carry the provider's
	// own output.
	e.scanChannels(tb, "image-build", inv, material, map[Channel]func() string{
		ChannelBuildLog: func() string {
			var logs bytes.Buffer
			_, _ = f.Build(tb, e, &logs)
			return logs.String()
		},
		ChannelBuildError: func() string {
			// A build that fails for a reason of its own -- a destination in no
			// repository -- rather than one the marker caused. The marker is
			// cleared before the scan, so a reader whose only source of failure
			// was the marker would scan a nil error: the channel would be
			// established and then read empty every time, which is the vacuity
			// this file exists to close, arriving through the mechanism meant to
			// close it.
			_, err := f.builder.Build(e.ctx, compute.BuildRequest{
				Source: compute.BuildSource{ContextDir: f.ContextDir},
				Destinations: []compute.ImageRef{
					compute.ImageRef("registry.invalid/conformance/absent:v1"),
				},
			})
			if err == nil {
				return ""
			}
			return err.Error()
		},
		ChannelBuildResult: func() string {
			res, _ := f.Build(tb, e, nil)
			if res == nil {
				return ""
			}
			return fmt.Sprint(*res)
		},
	})
}

// checkBuildOutputNotInError is USOSS-10's finding against the source system,
// checked from the other end.
//
// There, a failing build's error carries a tail of the builder's output, and
// that error is persisted onto a job record and rendered in an interface
// (build.go:566-572). The output is repository-authored — a RUN line prints
// whatever it likes — so the durable record of a failed build is a channel the
// repository's author writes into. The obligation is that a provider does not
// build that channel.
func checkBuildOutputNotInError(tb TB, e *Env) {
	const inv = "a failed build's error carries no builder output"
	f := buildFixture(tb, e)
	if f == nil {
		skipBecause(tb, e, inv, buildUnavailable(e))
		return
	}

	// One channel, the same call: the error is established as carrying the
	// provider's own output before it is searched for content read from the build
	// context.
	e.scanChannels(tb, "image-build", inv, []string{buildMarker}, map[Channel]func() string{
		ChannelBuildError: func() string {
			// A destination in no repository, so the build fails after reading
			// the context. A provider that interpolates what it read into the
			// failure puts the marker in the error.
			_, err := f.builder.Build(e.ctx, compute.BuildRequest{
				Source: compute.BuildSource{ContextDir: f.ContextDir},
				Destinations: []compute.ImageRef{
					compute.ImageRef("registry.invalid/conformance/absent:v1"),
				},
			})
			if err == nil {
				return ""
			}
			return err.Error()
		},
	})
}

// checkBuildCredentialsNotInImageMetadata is the fourth credential-egress
// channel USOSS-39 named and did not build.
//
// The other three -- log, error, result -- come straight back from a call to
// [compute.ImageBuilder.Build]. Image metadata does not: [compute.BuildResult]
// exposes none, so nothing here could previously tell a provider that folded
// its own scoped push credential into a build argument from one that never
// did. compute/conformance/drive.go recorded the gap by name rather than claim
// it was covered -- `rg BuildArgs compute/conformance compute/fake` found no
// planting, no read-back hook, no provider storage and no defect.
//
// The blast radius here is the largest of the four. A credential in Logs or an
// error reaches whoever reads that build's record; a credential baked into an
// image is published to every puller of it, the way `docker history` publishes
// every ARG a build consumed, for as long as the image exists.
func checkBuildCredentialsNotInImageMetadata(tb TB, e *Env) {
	const inv = "credentials made available to a build appear in no image metadata"
	f := buildFixture(tb, e)
	if f == nil {
		skipBecause(tb, e, inv, buildUnavailable(e))
		return
	}
	if e.Options.BuildCredentials == nil {
		skip(tb, e, inv, "Options.BuildCredentials, which has to report the material this "+
			"provider makes available to a build — the suite cannot know it, because the "+
			"interface deliberately never shows a minted credential to the caller")
		return
	}
	if e.Options.ImageMetadata == nil {
		skip(tb, e, inv, "Options.ImageMetadata, which has to read back the metadata this "+
			"provider recorded for a pushed image — the suite cannot know it any other way, "+
			"because compute.BuildResult exposes none")
		return
	}
	material, err := e.Options.BuildCredentials(e.ctx, e.Provider)
	if err != nil {
		fatal(tb, "image-build", inv, "Options.BuildCredentials failed: %v", err)
	}
	// A derivation returning nothing passes every check over it, the same
	// vacuity checkBuildCredentialsNotEmitted guards against.
	if len(material) == 0 {
		fail(tb, "image-build", inv, "Options.BuildCredentials reported no material, so the "+
			"scan below would search an image's metadata for nothing at all. A provider whose "+
			"build genuinely holds no credential should leave the hook nil, which is reported as "+
			"unverified rather than as a pass")
		return
	}

	e.scanChannels(tb, "image-build", inv, material, map[Channel]func() string{
		ChannelImageMetadata: func() string {
			_, _ = f.Build(tb, e, nil)
			meta, err := e.Options.ImageMetadata(e.ctx, e.Provider, f.Destination)
			if err != nil {
				fatal(tb, "image-build", inv, "Options.ImageMetadata failed: %v", err)
			}
			return meta
		},
	})
}

// checkBuildCacheDefaultIsBounded is the second obligation USOSS-39 named and
// did not build: [compute.BuildCache.MaxAge] documents that leaving it zero
// defers to "the provider's default, which must not be 'forever'", and
// nothing checked it.
//
// [compute.BuildCache] is an input with no corresponding output --
// [compute.ImageBuilder.Build] returns no cache policy -- so the effective
// retention a provider actually applies is not observable by driving a build
// at all, only by asking the provider directly.
func checkBuildCacheDefaultIsBounded(tb TB, e *Env) {
	const inv = `a build cache's default MaxAge, when the caller leaves it zero, is not "forever"`
	if !e.Provider.Capabilities().Has(compute.CapImageBuild) {
		skip(tb, e, inv, string(compute.CapImageBuild))
		return
	}
	if e.Options.BuildCacheDefaultMaxAge == nil {
		skip(tb, e, inv, "Options.BuildCacheDefaultMaxAge, which has to report the age at which "+
			"this provider expires a cached layer when compute.BuildCache.MaxAge is left zero — "+
			"the suite cannot observe it any other way, because BuildCache is an input with no "+
			"corresponding output")
		return
	}
	got, err := e.Options.BuildCacheDefaultMaxAge(e.ctx, e.Provider)
	if err != nil {
		fatal(tb, "image-build", inv, "Options.BuildCacheDefaultMaxAge failed: %v", err)
	}
	if got <= 0 {
		fail(tb, "image-build", inv, "the provider's default build-cache MaxAge is %s, which "+
			"this suite reads as \"forever\": a cached package-install layer keeps serving "+
			"whatever it captured, so a default that never expires means an upstream security "+
			"fix never reaches a rebuild of an unchanged recipe", got)
	}
}

// buildUnavailable explains why there is no build to drive, naming the
// capabilities rather than reporting a bare skip.
func buildUnavailable(e *Env) string {
	caps := e.Provider.Capabilities()
	switch {
	case !caps.Has(compute.CapImageBuild):
		return fmt.Sprintf("provider %q does not advertise %s, so it has no builder to drive",
			e.Provider.Name(), compute.CapImageBuild)
	default:
		return fmt.Sprintf("provider %q advertises %s and not %s, so it can be handed no legal "+
			"Destination: a build needs a repository this provider hosts to push to",
			e.Provider.Name(), compute.CapImageBuild, compute.CapImageRegistry)
	}
}
