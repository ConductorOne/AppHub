// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// The ECR actions a build needs, split by what they can be scoped to.
//
// This is the least-privilege machinery [compute.ImageBuilder] states as an
// obligation, and it is preserved from the source system verbatim
// (kaniko_creds.go:66-104) rather than re-derived. Two rules govern any change
// to it:
//
//   - ecr:GetAuthorizationToken is registry-level and AWS requires Resource "*".
//     It is the only action here that is not scoped, and it hands out a token
//     whose own permissions are the intersection of this session policy and the
//     role's — so the unscoped action does not widen anything.
//   - Every action that can read or write an image is scoped to the exact
//     repository ARNs of this build's destinations. Widening that list, or
//     reaching for a wildcard resource because a push failed, is a finding to
//     report rather than a fix to make.
//
// The cache repository used to be in that list, and USOSS-41 took it out. Not as
// a tightening for its own sake: since the build phase runs with no credential it
// cannot read or write a registry layer cache at all, so a scope covering the
// cache repository would authorise a write nothing performs. See
// [imageBuilder.cacheArgs].
var (
	registryLevelActions = []string{
		"ecr:GetAuthorizationToken",
	}
	repositoryScopedActions = []string{
		"ecr:BatchCheckLayerAvailability",
		"ecr:BatchGetImage",
		"ecr:CompleteLayerUpload",
		"ecr:GetDownloadUrlForLayer",
		"ecr:InitiateLayerUpload",
		"ecr:PutImage",
		"ecr:UploadLayerPart",
	}
)

// policyDocument, statement, and their JSON tags are the IAM policy grammar.
//
// Marshalled rather than formatted. The source system builds this document with
// fmt.Sprintf and quotes each ARN with %q (kaniko_creds.go:76-104), which is Go
// string quoting rather than JSON string quoting; they agree for the ARNs that
// actually occur, and a document assembled by string concatenation is the shape
// of defect that only shows up on the input nobody tried.
type policyDocument struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

type statement struct {
	Sid      string   `json:"Sid,omitempty"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource any      `json:"Resource"`
}

// maxSessionPolicyBytes is the ceiling AWS puts on an inline session policy
// passed to sts:AssumeRole.
//
// The documented limit is on plaintext characters and excludes whitespace; the
// document here is rendered by encoding/json with no whitespace at all, so the
// two counts coincide and one comparison is enough.
const maxSessionPolicyBytes = 2048

// pushSessionPolicy renders the session policy for a build pushing to arns.
//
// Two refusals, and both exist to keep the same wrong answer off the table.
//
// An empty list is refused, because a session policy with no resources is an
// empty intersection: every push fails, and the natural "fix" is a wildcard.
//
// A policy over [maxSessionPolicyBytes] is refused here rather than by the
// security token service. The policy grows by one repository ARN per
// destination, so a build with enough destinations produces one AWS rejects —
// and it rejects it with a validation error about policy syntax, from inside a
// credential mint, which is the least useful place for a caller to learn that
// its spec is too big. It fails closed either way; this is about the caller
// being told what to change, and being told that the change is not a wildcard.
func pushSessionPolicy(arns []string) (string, error) {
	if len(arns) == 0 {
		return "", fmt.Errorf("%w: a build needs at least one destination repository to scope "+
			"its push credential to", compute.ErrInvalidSpec)
	}
	scoped := append([]string(nil), arns...)
	sort.Strings(scoped)
	doc := policyDocument{
		Version: "2012-10-17",
		Statement: []statement{
			{
				Sid:      "RegistryAuth",
				Effect:   "Allow",
				Action:   registryLevelActions,
				Resource: "*",
			},
			{
				Sid:      "PushToTheseRepositoriesOnly",
				Effect:   "Allow",
				Action:   repositoryScopedActions,
				Resource: scoped,
			},
		},
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("%w: rendering the push session policy: %w", compute.ErrFailed, err)
	}
	if len(out) > maxSessionPolicyBytes {
		return "", fmt.Errorf("%w: this build scopes its push credential to %d repositories, "+
			"which renders a %d-character session policy, and the security token service accepts "+
			"at most %d. Reduce the number of destination repositories: widening the policy to a "+
			"wildcard resource would fit, and would hand a repository-authored build push access "+
			"to every repository in the account",
			compute.ErrInvalidSpec, len(scoped), len(out), maxSessionPolicyBytes)
	}
	return string(out), nil
}

// mintPushCredentials assumes the configured push role under a session policy
// scoped to arns, for the configured duration.
//
// The credential is returned to the pusher and to nothing else. It is never
// logged, never put in an error, never handed to the process that executed the
// Dockerfile, and never handed back across the [compute] interface; see
// [compute.ImageBuilder] for why the interface has no method that would make it
// visible to a caller.
//
// The call site is after the build, not before it (USOSS-41). That is worth
// stating here because "mint, then build, then push" is the obvious ordering and
// it is the wrong one: it puts a live credential in this process for the whole
// duration of a repository-authored build, which is also the whole duration in
// which the fifteen-minute lifetime can quietly expire under a slow build.
func (b *imageBuilder) mintPushCredentials(ctx context.Context, arns []string, sessionName string) (PushCredentials, error) {
	policy, err := pushSessionPolicy(arns)
	if err != nil {
		return PushCredentials{}, err
	}
	creds, err := b.p.sub.STS.AssumeRole(ctx, AssumeRoleRequest{
		RoleARN:     b.p.cfg.Build.PushRoleARN,
		SessionName: sessionName,
		Policy:      policy,
		Duration:    b.p.cfg.Build.sessionDuration(),
	})
	if err != nil {
		// Neither the policy, the role, NOR err itself is wrapped in. The policy
		// and role are a caller above the boundary has no use for and one of
		// which names an account; err is STS's own text, and [STSAPI] is an
		// interface a caller can supply its own adapter for, so its message is
		// exactly as untrusted as the substrate errors [Provider.substrateError]
		// classifies without retaining. Wrapping it back in here with a second
		// %w, after already asking substrateError to classify it, would leak it
		// through this call site regardless of what substrateError itself does.
		return PushCredentials{}, fmt.Errorf("%w: minting the build's scoped push credential",
			b.p.substrateError(err))
	}
	if creds.IsZero() {
		return PushCredentials{}, fmt.Errorf("%w: the security token service returned an empty "+
			"credential; refusing to run a repository-authored build with whatever the builder "+
			"would fall back to", compute.ErrFailed)
	}
	return creds, nil
}

// buildEnvAllowlist is the set of parent environment variables a build or a push
// may inherit.
//
// It is an allowlist built from scratch, not a filtered copy of the parent
// environment, and that is the whole design (kaniko_creds.go:120-131). A
// Dockerfile RUN instruction executes repository-authored code in this
// environment, so anything carried through is readable by whoever wrote the
// repository. A denylist would silently expose every variable added to apphub
// later; an allowlist fails safe by default and its failure mode is a build
// that needs a variable and says so.
//
// One list for both phases rather than two. The push phase runs a tool this
// operator chose rather than repository-authored code, so a wider list would be
// defensible — and it would be a second thing to keep right, for a process whose
// only job is to upload a file that already exists.
//
// Note what is deliberately absent: AWS_CONTAINER_CREDENTIALS_RELATIVE_URI and
// AWS_CONTAINER_CREDENTIALS_FULL_URI, the ambient task-role credential source.
// Carrying either through would hand the build apphub's own identity, which is
// the vulnerability the scoped credential exists to close.
var buildEnvAllowlist = map[string]struct{}{
	"PATH":          {},
	"HOME":          {},
	"SSL_CERT_FILE": {},
	"SSL_CERT_DIR":  {},
	"TMPDIR":        {},
	"LANG":          {},
	"container":     {},
}

// buildEnv composes the environment for the build phase.
//
// There is no credential in it and no field on [BuildCommand] that could carry
// one, which is USOSS-41's construction rather than this function's care.
//
// Two things are absent that a reader may expect, and both are deliberate:
//
//   - **No AWS credential**, obviously, and therefore
//   - **no region.** AWS_REGION was here to point the credential at an endpoint.
//     With no credential the build phase makes no AWS call — it builds a local
//     context and writes a tarball — so a region tells repository-authored code
//     where this deployment lives and buys nothing. See [pushEnv], which needs it.
//
// dockerConfigDir is passed as DOCKER_CONFIG rather than inherited, so the
// builder reads the configuration this build wrote and not whatever is at the
// builder's compiled-in default path. For the build phase that configuration is
// deliberately empty of credential helpers; see [imageBuilder.writeDockerConfig].
func buildEnv(parent []string, dockerConfigDir string) []string {
	env := allowedEnv(parent)
	if dockerConfigDir != "" {
		env = append(env, "DOCKER_CONFIG="+dockerConfigDir)
	}
	return env
}

// pushEnv composes the non-secret environment for the push phase.
//
// The credential is not in here and cannot be: it lives in
// [PushCommand.Credentials] and is turned into a variable only by the pusher
// that is about to exec. The region is, because the credential helper resolving
// an ECR token needs one.
func pushEnv(parent []string, region, dockerConfigDir string) []string {
	env := allowedEnv(parent)
	if region != "" {
		env = append(env, "AWS_REGION="+region, "AWS_DEFAULT_REGION="+region)
	}
	if dockerConfigDir != "" {
		env = append(env, "DOCKER_CONFIG="+dockerConfigDir)
	}
	return env
}

// allowedEnv is the allowlisted part of parent, and nothing else.
func allowedEnv(parent []string) []string {
	env := make([]string, 0, len(buildEnvAllowlist)+3)
	for _, kv := range parent {
		name, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, allowed := buildEnvAllowlist[name]; allowed {
			env = append(env, kv)
		}
	}
	return env
}

// dockerConfig renders a registry configuration mapping each host in hosts onto
// the "ecr-login" credential helper.
//
// It contains no credential material: the helper resolves a token from the AWS
// credentials in the process environment when it runs. That is worth stating
// plainly, because the natural reading of "the build writes a docker config" is
// that the config holds the credential, and here it does not.
//
// The mapping is scoped to the destination registries rather than applied
// globally, and that is load-bearing rather than tidy: with a global helper the
// tool tries to authenticate to Docker Hub with an ECR token and fails to pull
// any public base image (build.go:437-441).
//
// An empty hosts list is a legal and used argument: it renders a configuration
// that maps nothing, which is what the build phase gets. Since USOSS-41 that
// phase has no credential for a helper to find, so a helper mapping there would
// turn a pull of a base image in the operator's own registry from a clear
// authorization failure into a confusing helper failure — and a public base
// image, which is what a build with no registry credential can actually use,
// needs no helper at all.
func dockerConfig(hosts []string) (string, error) {
	helpers := make(map[string]string, len(hosts))
	for _, host := range hosts {
		helpers[host] = "ecr-login"
	}
	out, err := json.Marshal(map[string]any{"credHelpers": helpers})
	if err != nil {
		return "", fmt.Errorf("%w: rendering the builder's registry configuration: %w",
			compute.ErrFailed, err)
	}
	return string(out), nil
}
