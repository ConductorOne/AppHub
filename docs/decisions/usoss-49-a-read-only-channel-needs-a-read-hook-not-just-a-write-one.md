## USOSS-49 — a read-only channel needs a read hook, not just a write one

`compute/conformance` gains a fifth `Channel`, `ChannelImageMetadata`, and two new
`Options` hooks:

```go
ImageMetadata           func(ctx context.Context, p compute.Provider, image compute.ImageRef) (string, error)
BuildCacheDefaultMaxAge func(ctx context.Context, p compute.Provider) (time.Duration, error)
```

Two checks stand on them: `checkBuildCredentialsNotInImageMetadata` and
`checkBuildCacheDefaultIsBounded`, both in `compute/conformance/checks_build.go`.
`compute/fake` grows the fixtures that prove each can fail:
`DefectBuildCredentialInImageMetadata` and `DefectBuildCacheDefaultIsForever`.

### What USOSS-39 claimed and did not build

USOSS-39 drove `compute.ImageBuilder.Build` for the first time and said it
scanned four credential-egress channels — log, error, result, and image
metadata. It built three. `compute/conformance/drive.go` recorded the fourth as
an `obligation` rather than let the claim stand uncorrected: `rg BuildArgs
compute/conformance compute/fake` returned nothing, because a provider that
folded its own scoped push credential into a build argument had no channel here
that would notice. The same file recorded a second, unrelated gap next to it:
`compute.BuildCache.MaxAge` documents that a zero value defers to "the
provider's default, which must not be 'forever'", and nothing read that default
back to check it.

Both entries are gone from `unverifiedObligations` now. Neither was folded into
an existing check — `checkBuildCredentialsNotEmitted`'s invariant is "in no log,
error or result", and widening that sentence to include metadata would have
meant re-litigating every existing defect-table entry pinned to it for a claim
those entries never made.

### Why image metadata cannot be established the way the other three are

`ChannelBuildLog`, `ChannelBuildError`, and `ChannelBuildResult` are all read
directly from what a call to `Build` returns or is handed — the suite already
holds them, and `Options.EmitInto` only has to prove the provider can write into
them before a check trusts a clean scan. Image metadata is not returned by
`Build` at all; `compute.BuildResult` carries a `Digest` and nothing else. There
is no way for the suite to read it back without a second hook, so
`ChannelImageMetadata` needs both `EmitInto` (to arm a marker) and
`Options.ImageMetadata` (to read the image back) before `Env.scanChannels`'s
establish-then-scan machinery can run over it. A nil `ImageMetadata` hook is
guarded before `scanChannels` ever runs, precisely because `establish()` cannot
tell "the provider does not support this channel" apart from "the read hook is
missing" if the check lets it try: the first is `EmitInto` returning
`ErrChannelNotHostile`, a legitimate skip, and the second — an armed marker with
no way to read it back — would otherwise report the same marker as never having
arrived, which reads as a failure rather than as the absent capability it is.

### Why the fake still tells the two obligations apart

`compute/fake`'s `imageBuilder.build` now renders `req.BuildArgs` into a stored
metadata string on every build — the correct, non-defect behaviour, since
`BuildRequest.BuildArgs` is documented as landing there regardless. The defect
is not that credential-shaped material reaches metadata through `BuildArgs`;
a caller who does that violated the documented contract themselves, and no
check here is positioned to stop a caller from writing insecurely to a
field labelled non-secret. The defect this closes is the one
`compute/conformance/drive.go`'s obligation entry named: a *provider* that
folds *its own* scoped push credential into an image's metadata, the same way
`DefectBuildCredentialInLogs` and its siblings fold that credential into the
other three channels. `DefectBuildCredentialInImageMetadata` reproduces that
shape, not caller misuse of `BuildArgs`.

`checkBuildCacheDefaultIsBounded` needs no build at all — `BuildCache` is an
input with no corresponding output, so there is nothing to drive; the check
asks `Options.BuildCacheDefaultMaxAge` directly and requires a positive
duration.

### Verified in both directions

Removing the two new `Check` registrations from `buildChecks()` and re-running
`TestConformanceSuiteCatchesNonConformance` turned both new entries red: the
provider still exhibits `DefectBuildCredentialInImageMetadata` and
`DefectBuildCacheDefaultIsForever`, and the suite reported a clean pass anyway.
Restoring the registrations turned both green again, which is the fixture this
project's standing rule requires before a check earns a defect-table entry.
