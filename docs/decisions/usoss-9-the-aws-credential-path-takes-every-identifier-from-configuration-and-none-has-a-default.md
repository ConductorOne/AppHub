## USOSS-9 — the AWS credential path takes every identifier from configuration, and none has a default

*Recorded from USOSS-9, the port of the AWS-native credential providers. The
ticket's own words: "Zero hardcoded ARNs, account IDs, role names, or org-specific
paths; all config-driven with documented defaults." The last three words are the
one part of it not honoured, and this record says why.*

### A default is the identifier, moved

`backend/internal/credentials/claude.go` compiled in four values that name a
deployment rather than a protocol:

| source | value | now |
|---|---|---|
| `claude.go:26` | an IAM path naming the internal project | `StaticConfig.UserPath` |
| `claude.go:28` | an AWS managed policy granting broad Bedrock access | `StaticConfig.PolicyARN` |
| `claude.go:102`, `:230` | a two-letter resource-name prefix, the project's initials | `DynamicConfig.SessionNamePrefix`, `StaticConfig.UserNamePrefix` |
| `claude.go:66-69`, `:297-300` | a region | `Config.Region` |
| `claude.go:426-428`, `:447-449` | the project name, as the fallback for a name that sanitised to nothing | removed; the request is refused |

None of them has a default, and the ticket's "with documented defaults" is
declined deliberately. A default that is right for one deployment is that
deployment's identifier, compiled into a public repository — which is the thing
this ticket exists to remove, arriving under a different name. And a default that
is *not* right for the deployment running it is worse: an operator who forgot to
set the region gets a credential minted somewhere they did not choose, silently.

So `Config` has seven string fields, every one required, and `Config.Validate`
refuses an unset one by name without echoing the value. `TestEveryConfiguration
FieldIsRequiredAndHasNoDefault` derives that population from the reflect type
rather than from a list, so a field added later is required or the test fails.

### Which side of the interface each value sits on

The source read the role ARN, the region and the permissions boundary out of the
per-request metadata bag (`claude.go:66`, `:96`, `:236`). All three are now
operator configuration fixed at construction, and the provider reads no metadata
at all. This is a narrowing and it is the security half of the record:

- A caller-supplied `role_arn` means the vend request chooses which role the
  platform assumes. Any role whose trust policy admits the platform was reachable
  from a request.
- A caller-supplied policy ARN would let a request name its own grant.
- A boundary that a request may omit is not a boundary.

### The four fail-closed divergences, and the one that matters most

1. **A role is required for the dynamic path.** The source skipped the whole
   assume-role block when `role_arn` was absent (`claude.go:96-152`) and presigned
   with the platform's ambient credentials. A Bedrock bearer token authenticates as
   whoever signed it, so the requester received the platform's own privileges. This
   is the consequential one.
2. **A permissions boundary is required.** Optional in the source
   (`claude.go:236-238`), so the default path created an unbounded IAM user.
3. **A TTL is required and is never substituted.** The source defaulted a dynamic
   TTL to an hour (`claude.go:80-83`) and, for a static credential, omitted
   `CredentialAgeDays` when no TTL was given (`claude.go:255-261`) — which AWS
   documents as "the credential will not expire".
4. **A static TTL must be a whole number of days.** The source computed
   `int32(TTL.Hours()/24)` with a floor of 1 (`claude.go:256-259`), so a
   twelve-hour request became a twenty-four-hour credential. That is an extension
   of a lifetime policy had already clamped, in the one direction a credential
   lifetime must never move. Refusing and naming the granularity is this
   repository's rule for a substrate that cannot express what the interface
   permits.

### What is not claimed

`Config.Region` is validated as letters, digits and hyphens rather than against
AWS's region grammar. The grammar grows; what matters is that a region cannot
contain a dot or a slash, because the SDK interpolates it into an endpoint and
either character is an endpoint substitution. Refusing a region AWS later
introduces would be worse than accepting a string that is not one.

A role's own `MaxSessionDuration` can be lower than STS's twelve hours and is not
knowable from configuration, so a request above it is not refused locally. It
reaches STS and comes back classified. Guessing a lower ceiling would refuse
requests that would have worked.
