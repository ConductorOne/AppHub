// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// imageBuilder implements [compute.ImageBuilder] by running kaniko as a
// subprocess and then pushing what it produced from a second one.
//
// # Why a subprocess is the port's shape here
//
// The builder is not an API client. [compute.ImageBuilder] says so and the
// source system is the reason: it execs /kaniko/executor (build.go:539-576).
// Everything interesting about this port is therefore about what that
// subprocess can reach, not about which API it calls.
//
// # Why there are two of them
//
// USOSS-41. kaniko unpacks the image into the container it runs in and shares a
// PID namespace with the commands it runs, so a RUN instruction is
// repository-authored code executing inside the process this package started. A
// build that pushes is therefore a build whose own environment holds a live
// registry credential, and the source system's leak (a tail of that process's
// output, appended to an error, persisted onto a job record) is one exfiltration
// route out of an unbounded set.
//
// So the build does not push. kaniko runs with --no-push and writes a tarball;
// the credential is minted afterwards and handed to [ImagePusher], which runs a
// process that never executed a line of the Dockerfile. What that closes, and
// the same-user /proc residue it does not, is written out on [ImagePusher].
//
// # What a repository author controls, and what they can reach
//
// A Dockerfile RUN instruction executes code the repository's author wrote,
// inside a process this package starts. So the honest question is what an
// attacker who controls a build input can do:
//
//   - **Argument injection: no.** Every argument is passed as one argv element
//     in --flag=value form, so a value cannot be read as a flag however it is
//     spelled, and there is no shell anywhere on the path — [BuildRunner]
//     receives an executable and a slice, never a command line. On top of that
//     the values are bounded: a destination must resolve to a repository this
//     provider itself issued, a tag must match the registry's tag grammar, a
//     build argument's name must be an identifier, and no value may contain a
//     NUL or a newline.
//
//   - **Pushing somewhere else: no.** Destinations are matched against the
//     repositories this provider issued, by URI prefix, and anything else is
//     [compute.ErrInvalidSpec] before a credential is minted. A build cannot
//     name a registry the operator did not configure, so it cannot be handed a
//     credential for one.
//
//   - **Reading apphub's own credentials: no.** The environment is an
//     allowlist built from scratch and the ambient container-credential
//     variables are not in it. See [buildEnvAllowlist].
//
//   - **Reading the credential this build pushes with: no.** There is none to
//     read. [BuildCommand] has no field that can carry a credential, the build
//     phase's environment has no AWS credential in it of any kind, and while the
//     Dockerfile is executing no credential for this build has been minted yet.
//     See [ImagePusher].
//
//   - **Reaching another repository in the same registry: no.** The session
//     policy names the destination repository ARNs and nothing else, so the
//     token the credential helper obtains is already narrowed. See
//     [pushSessionPolicy].
//
//   - **Overwriting an existing tag: yes, unless the operator configured
//     immutable tags.** The source system pushes a ":latest" and therefore
//     needs mutable tags (build.go:307), so this is [RegistryConfig.ImmutableTags]
//     rather than a fixed hardening.
//
//   - **Reading the build context: yes, entirely.** That is what a build is.
//     The confinement that remains is that the *recipe* cannot escape the
//     context — see [resolveDockerfile].
//
//   - **Using the registry layer cache: no, and this is a cost rather than a
//     hardening.** A credential-free build phase cannot read or write a cache in
//     a private registry. See [imageBuilder.cacheArgs].
//
//   - **Spending money and time: yes.** Nothing here bounds a build's duration;
//     the caller's context does, and [compute.ImageBuilder.Build] says
//     cancellation is via ctx.
type imageBuilder struct{ p *Provider }

var _ compute.ImageBuilder = (*imageBuilder)(nil)

// buildSessionPrefix names the STS session in CloudTrail, so a push made by a
// build is distinguishable from one made by anything else.
const buildSessionPrefix = "apphub-build"

// Build produces and pushes the requested images.
//
// The wrapper is the hostile-mode seam. A build-error emission decorates
// **whatever** error the build returns, rather than one route through it: the
// channel the conformance suite names is "the error a build returns", and its own
// failing-build fixture names a destination in no repository, which fails during
// target resolution — well before the mid-function emission point this used to
// have. A hook that emits on one route out of several buys a green for every scan
// standing on the channel, which is the false declaration the marker mechanism
// exists to rule out.
func (b *imageBuilder) Build(ctx context.Context, req compute.BuildRequest) (*compute.BuildResult, error) {
	res, err := b.build(ctx, req)
	m := b.p.emission(ChannelBuildError)
	if m == "" {
		return res, err
	}
	if err == nil {
		return nil, fmt.Errorf("aws: build failed%s: %w", m, compute.ErrFailed)
	}
	return nil, fmt.Errorf("%w%s", err, m)
}

func (b *imageBuilder) build(ctx context.Context, req compute.BuildRequest) (*compute.BuildResult, error) {
	if len(req.Destinations) == 0 {
		return nil, fmt.Errorf("%w: a build needs at least one destination", compute.ErrInvalidSpec)
	}
	logf := func(format string, args ...any) {
		if req.Logs != nil {
			_, _ = fmt.Fprintf(req.Logs, format+"\n", args...)
		}
	}

	root, dockerfile, err := resolveDockerfile(req.Source)
	if err != nil {
		return nil, err
	}
	if err := b.checkContextSize(root); err != nil {
		return nil, err
	}
	buildArgs, err := renderBuildArgs(req.BuildArgs)
	if err != nil {
		return nil, err
	}

	// Everything the build may touch, resolved against repositories this
	// provider issued. This runs before a credential is minted, so a build
	// naming somewhere else never gets one.
	targets, err := b.resolveTargets(ctx, req)
	if err != nil {
		return nil, err
	}

	// Two private directories, one per phase, each holding that phase's registry
	// configuration. Neither holds credential material — see [dockerConfig] —
	// but both are provider-written state in a directory a subprocess can read,
	// so each is created with the tightest permissions the platform has and
	// removed unconditionally.
	//
	// They are separate rather than shared, and it is not tidiness: the build
	// phase's configuration maps no registry onto a credential helper, so even a
	// build phase that somehow acquired an AWS credential has no configured route
	// to the operator's registry. The push phase's configuration is the one with
	// the helper mapping, and the build phase cannot see it.
	//
	// The source system writes one configuration to a fixed path,
	// /kaniko/.docker/config.json (build.go:584-616), and never removes it. Two
	// consequences it does not intend: two builds in one process race on one
	// file, and the last build's configuration is what the next one reads if its
	// own write fails. A per-build directory named through DOCKER_CONFIG closes
	// both.
	//
	// The removals are deferred before the errors are checked, on purpose: a
	// partially created directory still has to go, and putting the cleanup on the
	// success path is how a temporary file outlives the process that needed it.
	buildDir, cleanupBuild, err := b.writeDockerConfig(nil)
	defer cleanupBuild()
	if err != nil {
		return nil, err
	}
	pushDir, cleanupPush, err := b.writeDockerConfig(targets.hosts())
	defer cleanupPush()
	if err != nil {
		return nil, err
	}

	artefact := filepath.Join(buildDir, buildArtefactName)
	digestFile := filepath.Join(buildDir, "digest")

	args := []string{
		"--context=" + root,
		"--dockerfile=" + dockerfile,
		// The three flags that make this a build rather than a publish. Kaniko
		// treats not-pushing-the-image and not-pushing-the-cache as separate
		// decisions -- that is why --no-push-cache exists as its own flag, and
		// it is registered separately in v1.28.4 -- so passing both is not
		// redundant. --cache=false makes the second one moot today; it stays
		// because "this process performs no registry write" is the property, and
		// a property that depends on another flag's value is one a later edit
		// can lose without noticing.
		"--no-push",
		"--no-push-cache",
		"--tar-path=" + artefact,
	}
	args = append(args, b.cacheArgs(req.Cache, logf)...)
	args = append(args, buildArgs...)
	// Still passed, and still validated, though nothing is pushed here: kaniko
	// names the image in the tarball after its destinations, and it refuses a
	// --tar-path build that names none.
	for _, dest := range targets.destinations {
		args = append(args, "--destination="+dest)
	}
	args = append(args, "--digest-file="+digestFile)

	logf("building %s from %s", strings.Join(targets.destinations, ", "), dockerfile)
	// The build phase's output goes to the caller's writer unwrapped, and that is
	// a consequence of the construction rather than a relaxation of it: at this
	// point in the function no credential for this build exists anywhere, so
	// there is nothing for a redactor to look for. The push phase's output is
	// wrapped, below, because that is where material exists.
	err = b.p.sub.Builder.Run(ctx, BuildCommand{
		Executable: b.p.cfg.Build.ExecutorPath,
		Args:       args,
		Dir:        root,
		Env:        buildEnv(os.Environ(), buildDir),
		Output:     req.Logs,
	})
	if err != nil {
		return nil, b.p.substrateError(err)
	}
	if err := checkArtefact(artefact); err != nil {
		return nil, err
	}

	// Only now, with something to push and the repository-authored part of the
	// build over, does a credential come into existence.
	creds, err := b.mintPushCredentials(ctx, targets.arns(), sessionName(targets))
	if err != nil {
		return nil, err
	}
	// The pusher's output is redacted on its way to the caller, because a pusher
	// cannot be assumed to honour its obligation not to echo its own
	// environment. See [redactingWriter] for what that closes and what it does
	// not.
	out := newRedactingWriter(req.Logs, creds)
	defer flush(out)
	if err := b.pushAll(ctx, targets, artefact, pushDir, creds, out, logf); err != nil {
		// Redacted before it is mapped, so no path from here to the caller can
		// carry the credential. See redactCredentials for what this does and
		// does not defend against.
		return nil, b.p.substrateError(redactCredentials(err, creds))
	}

	images := make([]compute.ImageRef, len(targets.destinations))
	for i, dest := range targets.destinations {
		images[i] = compute.ImageRef(dest)
	}
	// Read the builder's digest while the file still exists. The directory that
	// holds it is removed by the deferred cleanup, and that cleanup runs after
	// this function returns.
	//
	// It is not the digest the workload may run. Kaniko records the manifest it
	// built; crane push re-encodes that tarball, and the registry stores a
	// different manifest. ECS pulls by the digest it is given, so a task pinned
	// to Kaniko's digest fails with CannotPullContainerError even though the
	// tagged image is sitting in the repository. The digest below is the one
	// the registry reports for the tag that was just pushed.
	local := readDigest(digestFile)
	published, err := b.publishedDigest(ctx, targets.destinations)
	if err != nil {
		return nil, err
	}
	if local != "" && local != published {
		logf("the builder recorded digest %s; the registry stored %s. The workload runs the registry digest",
			local, published)
	}
	// The digest is the result channel: it is documented as optional and opaque
	// ("Empty otherwise; callers must not require it"), so a marker can ride there
	// without breaking a caller that reads it.
	return &compute.BuildResult{
		Images: images,
		Digest: published + b.p.emission(ChannelBuildResult),
	}, nil
}

// publishedDigest reads back the manifest digest the registry stored for every
// destination. They are one image pushed to several tags, so the digests have
// to agree; a disagreement means the pushes did not land the same manifest.
func (b *imageBuilder) publishedDigest(ctx context.Context, destinations []string) (string, error) {
	if b.p.sub.ECR == nil {
		return "", fmt.Errorf("%w: the image was pushed and this provider has no registry "+
			"client to read its digest back", compute.ErrFailed)
	}
	var published string
	for _, dest := range destinations {
		repo, suffix, err := splitImageRef(dest)
		if err != nil {
			return "", err
		}
		var tag, digest string
		switch {
		case strings.HasPrefix(suffix, ":"):
			tag = strings.TrimPrefix(suffix, ":")
		case strings.HasPrefix(suffix, "@"):
			digest = strings.TrimPrefix(suffix, "@")
		default:
			return "", fmt.Errorf("%w: %q has no tag, so the digest the registry stored cannot "+
				"be read back", compute.ErrInvalidSpec, dest)
		}
		got, err := b.p.sub.ECR.DescribeImage(ctx, repo, tag, digest)
		if err != nil {
			if errors.Is(err, ErrNoSuchResource) {
				return "", fmt.Errorf("%w: %s was pushed and the registry has no image there, so "+
					"a workload pinned to the builder's own digest could not pull it",
					compute.ErrFailed, dest)
			}
			return "", b.p.substrateError(err)
		}
		if !imageDigest.MatchString(got) {
			return "", fmt.Errorf("%w: the registry reported %q for %s, which is not a digest",
				compute.ErrFailed, got, dest)
		}
		if published == "" {
			published = got
			continue
		}
		if got != published {
			return "", fmt.Errorf("%w: %s is digest %s and another destination of this build is "+
				"%s. One workload cannot be pinned to both", compute.ErrFailed, dest, got, published)
		}
	}
	return published, nil
}

// cacheArgs renders the layer-cache flags, which are always "off".
//
// # This is USOSS-41's price, and it is a real one
//
// kaniko's layer cache is a repository in the registry: it reads cached layers
// from it and writes new ones to it. Both need a registry credential, and the
// build phase deliberately has none — so the cache cannot be used, and saying
// that plainly is better than a flag that looks enabled and fails at runtime.
//
// [compute.BuildRequest.Cache] anticipates exactly this: "a build with no cache
// is slower but correct, so a provider that cannot cache should log and proceed
// rather than fail". So the cache repository a caller names is still resolved and
// still refused if it belongs to somebody else — a spec error is a spec error —
// and then it is logged and not used.
//
// # Why not a cache-scoped credential for the build phase
//
// It is the obvious way to keep caching: mint a second credential covering the
// cache repository only, and hand *that* to the build. It was rejected, and the
// reason is worth recording so it is not re-proposed as an optimisation.
//
// A credential a repository author can steal from the build phase is a
// credential they can use, and write access to a cache repository is a
// cache-poisoning primitive: cache repositories are shared between builds by
// construction (that is what makes them useful), so a poisoned layer is code
// execution inside somebody else's image. Read-only would avoid that and still
// hand out every cached layer of every application sharing the repository. Either
// way the class this ticket closes reopens, one notch smaller.
//
// # What would restore it
//
// A phase that runs before the build, holds the credential, and stages the cache
// onto local disk for the build phase to read — kaniko's --cache-repo accepts an
// "oci:" prefix, which may be enough. It is not implemented here because it
// cannot be validated without a real kaniko, which is the same constraint this
// ticket's own acceptance criteria name. USOSS-80 replaces kaniko with BuildKit,
// whose cache import/export is driven from outside the build, and that is the
// right place for it.
func (b *imageBuilder) cacheArgs(cache *compute.BuildCache, logf func(string, ...any)) []string {
	if cache == nil || cache.Repository == "" {
		logf("no build cache configured; the build is slower but correct")
	} else {
		logf("the build cache in %s is not used: the build phase runs with no registry "+
			"credential, so it can neither read nor write one. The build is slower but correct",
			cache.Repository)
	}
	return []string{"--cache=false"}
}

// buildArtefactName is the file the build phase writes and the push phase reads.
//
// A tarball rather than an OCI layout directory, because that is what the pusher
// this provider composes a command line for reads. See [imageBuilder.pushAll].
const buildArtefactName = "image.tar"

// checkArtefact refuses to mint a credential for a build that produced nothing.
//
// A builder that exits zero and writes no tarball is not a successful build, and
// the two failure modes it would otherwise produce are both bad: a push of a
// missing file, diagnosed by whatever the pusher says about a path; or, if the
// pusher is forgiving, a build reported as successful that published nothing and
// left the next deploy pulling an image nobody pushed.
//
// It is checked before the mint rather than after, so a build with nothing to
// publish does not cause a credential to exist.
func checkArtefact(path string) error {
	info, err := os.Stat(path)
	switch {
	case err != nil:
		return fmt.Errorf("%w: the builder exited successfully and wrote no image to %s: %w",
			compute.ErrFailed, filepath.Base(path), err)
	case !info.Mode().IsRegular() || info.Size() == 0:
		return fmt.Errorf("%w: the builder exited successfully and %s is empty or not a file, so "+
			"there is nothing to push", compute.ErrFailed, filepath.Base(path))
	}
	return nil
}

// pushAll publishes the artefact to every destination, from a process that never
// executed the Dockerfile.
//
// # The command line
//
// "push <artefact> <destination>", which is the grammar of crane
// (github.com/google/go-containerregistry) and the reason
// [BuildConfig.PusherPath] documents what an operator's binary has to accept.
// Two positional arguments rather than the --flag=value form the rest of this
// package insists on, because that is the tool's interface — and it is safe here
// for a reason a reader should not have to reconstruct: neither value is caller
// text. The artefact path is composed from a directory this process created, and
// a destination has already been required to equal, byte for byte, the URI the
// registry itself reported for a repository this provider issued. Neither can
// begin with a hyphen.
//
// # One invocation per destination
//
// Because "push" takes one destination. The layers are uploaded once and then
// found already present, since a registry addresses them by digest — so N
// destinations in one repository cost one upload and N manifest writes.
//
// The working directory is the push phase's own configuration directory, not the
// build context: there is no reason for the process holding the credential to
// have repository-authored content as its working directory.
func (b *imageBuilder) pushAll(
	ctx context.Context,
	targets buildTargets,
	artefact, configDir string,
	creds PushCredentials,
	out io.Writer,
	logf func(string, ...any),
) error {
	env := pushEnv(os.Environ(), b.p.cfg.Region, configDir)
	for _, dest := range targets.destinations {
		logf("pushing %s", dest)
		if err := b.p.sub.Pusher.Push(ctx, PushCommand{
			Executable:  b.p.cfg.Build.PusherPath,
			Args:        []string{"push", artefact, dest},
			Dir:         configDir,
			Env:         env,
			Credentials: creds,
			Output:      out,
		}); err != nil {
			return err
		}
	}
	return nil
}

// --- destinations -------------------------------------------------------------

// buildTargets is everything a build may touch, resolved.
type buildTargets struct {
	// destinations are the fully-qualified references to push, in the order
	// the caller asked for them, because [compute.BuildResult] promises that
	// order.
	destinations []string
	// repositories maps each repository name onto its ARN. It is keyed by name
	// so that two destinations differing only in tag scope one repository.
	repositories map[string]string
	// registryHosts is the set of registry hostnames involved.
	registryHosts map[string]struct{}
}

func (t buildTargets) arns() []string {
	out := make([]string, 0, len(t.repositories))
	for _, arn := range t.repositories {
		out = append(out, arn)
	}
	sort.Strings(out)
	return out
}

func (t buildTargets) hosts() []string {
	out := make([]string, 0, len(t.registryHosts))
	for host := range t.registryHosts {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func (t buildTargets) names() []string {
	out := make([]string, 0, len(t.repositories))
	for name := range t.repositories {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// sessionName names the STS session after what the build is pushing.
//
// It is derived rather than fixed — the source system uses the constant
// "kaniko-build" (kaniko_creds.go:182) — so that CloudTrail shows which
// repository a push belonged to. AWS bounds the field at 64 characters of a
// restricted alphabet, so it is sanitized and truncated the same way every
// other physical name in this package is.
const maxSessionName = 64

func sessionName(targets buildTargets) string {
	names := targets.names()
	if len(names) == 0 {
		return buildSessionPrefix
	}
	// A session name is a label in an audit trail, not a resource identity, so
	// a name this provider cannot render is degraded to the constant rather
	// than failing the build. Two builds may legitimately share one session
	// name; nothing is looked up by it.
	out, err := sanitizeWith(buildSessionPrefix+"-", names[0], maxSessionName, digestMarker)
	if err != nil {
		return buildSessionPrefix
	}
	return out
}

// imageTag is the registry's tag grammar, and the only part of a destination a
// caller composes freely.
var imageTag = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

// imageDigest is the other legal suffix.
var imageDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// resolveTargets maps every reference a build names onto a repository this
// provider issued, refuses anything else, and records which of them the push
// phase is to be authorised for.
//
// Refusing is the fail-closed half of the credential design. A destination
// somewhere else could only be pushed to with a credential for somewhere else,
// and the session policy is built from exactly this list — so a build that
// could name an arbitrary registry would be a build that could ask for an
// arbitrary scope.
func (b *imageBuilder) resolveTargets(ctx context.Context, req compute.BuildRequest) (buildTargets, error) {
	targets := buildTargets{
		repositories:  map[string]string{},
		registryHosts: map[string]struct{}{},
	}
	// scoped says whether the repository this reference names is one the push
	// phase will write to, and therefore one the session policy has to cover. A
	// reference that is validated and not scoped is still fully resolved — the
	// refusal is the point of resolving it — it simply authorises nothing.
	add := func(ref, what string, scoped bool) error {
		repo, suffix, err := splitImageRef(ref)
		if err != nil {
			return fmt.Errorf("%w (%s %q)", err, what, ref)
		}
		rec, err := b.lookupRepository(ctx, repo)
		if err != nil {
			return err
		}
		// The reference has to reconstruct exactly from the URI the registry
		// reported. This is what confines a build to the operator's own
		// registry: splitImageRef takes the repository name from after the
		// first slash, so "somewhere-else.invalid/app:v1" would otherwise find
		// the repository "app" in the configured registry and be pushed
		// somewhere the operator never named. It is a comparison rather than a
		// host check because the URI is the registry's own answer to "where is
		// this repository", and nothing else here has to know its shape.
		if rec.URI+suffix != ref {
			return fmt.Errorf("%w: %s %q does not name a repository in this provider's registry; "+
				"a build must not be given a credential for a registry the operator did not "+
				"configure", compute.ErrInvalidSpec, what, ref)
		}
		if !scoped {
			return nil
		}
		targets.repositories[rec.Name] = rec.ARN
		host, _, _ := strings.Cut(rec.URI, "/")
		targets.registryHosts[host] = struct{}{}
		return nil
	}

	for _, dest := range req.Destinations {
		if err := add(string(dest), "destination", true); err != nil {
			return buildTargets{}, err
		}
		targets.destinations = append(targets.destinations, string(dest))
	}
	if req.Cache != nil && req.Cache.Repository != "" {
		// Resolved and refused by the same rule as a destination, and then not
		// scoped to. The cache repository used to be in the credential's scope
		// because kaniko pulled cached layers from it and pushed new ones
		// (build.go:527-533); since USOSS-41 the build phase has no credential
		// and does neither, so scoping to it would authorise a write nothing
		// performs. See [imageBuilder.cacheArgs].
		//
		// The validation stays because a caller naming somebody else's
		// repository has a spec bug whether or not this provider would have used
		// it, and because a refusal that appears when caching is restored is a
		// refusal nobody tested.
		if err := add(req.Cache.Repository, "cache repository", false); err != nil {
			return buildTargets{}, err
		}
	}
	return targets, nil
}

// lookupRepository finds the repository a reference names and establishes that
// this platform owns it, by the URI and tags the registry reported.
//
// The ownership half is not incidental. Being in the operator's registry is not
// the same as being apphub's: review found that a build would mint a scoped
// push credential against a same-registry repository somebody else owned, and
// then push to it. Resolving through the registry's own [ownedRepository] gate
// means a build cannot obtain the ARN it would need without the ownership tags
// having been read.
//
// The source system recovers the account, region and repository from a
// destination with a regexp and rebuilds an ARN from a template
// (kaniko_creds.go:26-47). That works, and it means the ARN a session policy is
// scoped to is composed from caller-influenced text by a second, local
// definition of a string AWS owns. Here the reference is used only to find the
// repository, and the ARN comes back from the registry.
func (b *imageBuilder) lookupRepository(ctx context.Context, name string) (*RepositoryRecord, error) {
	reg := &imageRegistry{p: b.p}
	owned, found, err := reg.ownedByName(ctx, name)
	switch {
	case err != nil:
		return nil, err
	case !found:
		return nil, fmt.Errorf("%w: %q is not a repository this provider issued; a build must not "+
			"be given a credential for a registry the operator did not configure",
			compute.ErrInvalidSpec, name)
	}
	return &owned.rec, nil
}

// splitImageRef splits a fully-qualified reference into the repository name and
// the ":tag" or "@digest" suffix, validating the suffix.
//
// The repository half is not validated here: it is looked up, which is a
// stronger check than any grammar, and a name that does not exist is refused by
// the lookup.
func splitImageRef(ref string) (repo, suffix string, err error) {
	if ref == "" {
		return "", "", fmt.Errorf("%w: an image reference is empty", compute.ErrInvalidSpec)
	}
	if strings.ContainsAny(ref, "\x00\n\r \t") {
		return "", "", fmt.Errorf("%w: an image reference contains whitespace or a control "+
			"character", compute.ErrInvalidSpec)
	}
	host, path, ok := strings.Cut(ref, "/")
	if !ok || host == "" || path == "" {
		return "", "", fmt.Errorf("%w: an image reference must be registry-qualified",
			compute.ErrInvalidSpec)
	}
	if at := strings.LastIndex(path, "@"); at >= 0 {
		digest := path[at+1:]
		if !imageDigest.MatchString(digest) {
			return "", "", fmt.Errorf("%w: %q is not a digest this provider recognises",
				compute.ErrInvalidSpec, digest)
		}
		return path[:at], "@" + digest, nil
	}
	if colon := strings.LastIndex(path, ":"); colon >= 0 {
		tag := path[colon+1:]
		if !imageTag.MatchString(tag) {
			return "", "", fmt.Errorf("%w: %q is not a legal image tag", compute.ErrInvalidSpec, tag)
		}
		return path[:colon], ":" + tag, nil
	}
	return path, "", nil
}

// --- build arguments -----------------------------------------------------------

// buildArgName is the identifier grammar a build argument's name has to match.
var buildArgName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// renderBuildArgs validates and renders [compute.BuildRequest.BuildArgs].
//
// Sorted, so two builds of the same request produce the same command line and a
// rendered artefact is comparable. Validated, because these are the one part of
// a build's command line whose name as well as value comes from the caller —
// and although the --flag=value form means a value can never be read as a flag,
// a name that is not an identifier is a spec bug worth reporting rather than
// passing on to the builder.
//
// The interface is explicit that these are not secret: build arguments are
// recorded in image metadata and readable by anyone who can pull the image.
// This provider does not check that, because it cannot — it is a contract on
// the caller, and restating it here would be a check that catches nothing.
func renderBuildArgs(args map[string]string) ([]string, error) {
	names := make([]string, 0, len(args))
	for name := range args {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		if !buildArgName.MatchString(name) {
			return nil, fmt.Errorf("%w: build argument %q is not a legal variable name",
				compute.ErrInvalidSpec, name)
		}
		if strings.ContainsAny(args[name], "\x00\n\r") {
			return nil, fmt.Errorf("%w: the value of build argument %q contains a NUL or a "+
				"newline", compute.ErrInvalidSpec, name)
		}
		out = append(out, "--build-arg="+name+"="+args[name])
	}
	return out, nil
}

// --- the build context ----------------------------------------------------------

// resolveDockerfile confines the recipe to the build context and returns both
// resolved paths.
//
// The source system performs a prefix comparison on the cleaned join
// (build.go:462-467), which stops "../" and is what this replaces. Two things
// are added:
//
//   - Symbolic links are resolved on both sides before comparison. Without
//     that, a repository shipping a Dockerfile that is a symlink out of its own
//     tree has the platform build somebody else's file — the same escape the
//     original check exists to prevent, taken by a different route.
//   - The context directory itself is required to exist and be a directory,
//     rather than discovered to be neither by the builder.
func resolveDockerfile(src compute.BuildSource) (root, dockerfile string, err error) {
	if strings.TrimSpace(src.ContextDir) == "" {
		return "", "", fmt.Errorf("%w: a build needs a context directory", compute.ErrInvalidSpec)
	}
	root, err = filepath.Abs(src.ContextDir)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", compute.ErrInvalidSpec, err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return "", "", fmt.Errorf("%w: the build context %q is not a readable directory",
			compute.ErrInvalidSpec, src.ContextDir)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", fmt.Errorf("%w: resolving the build context: %w", compute.ErrInvalidSpec, err)
	}

	name := src.Dockerfile
	if name == "" {
		name = "Dockerfile"
	}
	if filepath.IsAbs(name) {
		return "", "", fmt.Errorf("%w: the Dockerfile path %q is absolute; it is relative to the "+
			"build context", compute.ErrInvalidSpec, src.Dockerfile)
	}
	full := filepath.Clean(filepath.Join(realRoot, name))
	realFull, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", "", fmt.Errorf("%w: the Dockerfile %q is not readable", compute.ErrInvalidSpec, name)
	}
	rel, err := filepath.Rel(realRoot, realFull)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("%w: the Dockerfile path %q resolves outside the build context",
			compute.ErrInvalidSpec, src.Dockerfile)
	}
	if info, err := os.Stat(realFull); err != nil || info.IsDir() {
		return "", "", fmt.Errorf("%w: the Dockerfile path %q is not a file",
			compute.ErrInvalidSpec, src.Dockerfile)
	}
	return realRoot, filepath.ToSlash(rel), nil
}

// checkContextSize bounds how much repository-authored content a build is handed.
//
// It used to say "handed to a process holding a push credential", which is no
// longer what happens: since USOSS-41 the process that reads the context holds no
// credential. The bound is kept because an unbounded context is an unbounded
// build, which is the reason that survives.
//
// [compute.BuildSource] obliges a provider whose builder does not share the
// caller's filesystem to document the size limit at which it refuses. This
// builder is a subprocess and does share it, so nothing is transported — but
// the bound is worth keeping anyway, because an unbounded context is an
// unbounded build, and [BuildConfig.MaxContextBytes] is where an operator says
// how much is too much.
func (b *imageBuilder) checkContextSize(root string) error {
	limit := b.p.cfg.Build.maxContextBytes()
	var total int64
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			// A file that vanished between the walk and the stat is not a
			// reason to fail a build.
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		total += info.Size()
		if total > limit {
			return errContextTooLarge
		}
		return nil
	})
	switch {
	case errors.Is(err, errContextTooLarge):
		return fmt.Errorf("%w: the build context under %q exceeds Config.Build.MaxContextBytes "+
			"(%d bytes)", compute.ErrInvalidSpec, root, limit)
	case err != nil:
		return fmt.Errorf("%w: reading the build context: %w", compute.ErrInvalidSpec, err)
	}
	return nil
}

// errContextTooLarge stops the walk early. It never reaches a caller.
var errContextTooLarge = errors.New("aws: build context exceeds the configured limit")

// --- the builder's registry configuration -----------------------------------------

// The permissions a phase's configuration directory and file are created with.
// The directory is owner-only so nothing else on the machine can enumerate it;
// the file is owner-read-write for the same reason.
//
// Owner-only is as far as file permissions reach here, and it is worth being
// clear about the limit: the build phase and the push phase run as the same user,
// so these modes stop another user on the machine and not a build. What stops a
// build from reading the push phase's configuration is that it is never told
// where it is, and that the file holds no credential anyway.
const (
	dockerConfigDirMode  fs.FileMode = 0o700
	dockerConfigFileMode fs.FileMode = 0o600
)

// writeDockerConfig writes a registry configuration for the hosts in hosts into
// a directory private to this build, and returns a cleanup that removes it.
//
// Called twice per build, and an empty hosts list is one of the two calls: the
// build phase gets a configuration that maps no registry onto a credential
// helper. See [dockerConfig].
//
// The cleanup is returned even when the write fails, so a caller can defer it
// before checking the error. A cleanup on the success path only is how a
// directory outlives the process that needed it.
func (b *imageBuilder) writeDockerConfig(hosts []string) (dir string, cleanup func(), err error) {
	cleanup = func() {}
	doc, err := dockerConfig(hosts)
	if err != nil {
		return "", cleanup, err
	}
	dir, err = os.MkdirTemp("", "apphub-build-")
	if err != nil {
		return "", cleanup, fmt.Errorf("%w: creating the builder's configuration directory: %w",
			compute.ErrFailed, err)
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	// MkdirTemp already creates the directory 0700; setting it explicitly is
	// how that stops being an assumption about somebody else's implementation.
	if err := os.Chmod(dir, dockerConfigDirMode); err != nil {
		return dir, cleanup, fmt.Errorf("%w: securing the builder's configuration directory: %w",
			compute.ErrFailed, err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(doc), dockerConfigFileMode); err != nil {
		return dir, cleanup, fmt.Errorf("%w: writing the builder's registry configuration: %w",
			compute.ErrFailed, err)
	}
	return dir, cleanup, nil
}

// readDigest recovers the image digest the build phase wrote, if it wrote one.
//
// [compute.BuildResult.Digest] is optional and callers must not require it, so
// every failure here is silent and yields the empty string: a build that
// succeeded is not turned into a failure by a missing diagnostic file. The
// value is validated rather than trusted, because it is read from a file a
// subprocess wrote.
func readDigest(path string) string {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is composed here, from a directory this process created.
	if err != nil {
		return ""
	}
	digest := strings.TrimSpace(string(raw))
	if !imageDigest.MatchString(digest) {
		return ""
	}
	return digest
}
