## USOSS-26 — `DeleteScope` gains a documented contract, and a conformance check

The AWS secret store found that `compute.SecretStore.DeleteScope` had **no**
coverage in `compute/conformance`. It is the call that stops a torn-down
application's credentials from outliving it, and the interface documents it as
existing precisely because the caller does not reliably know the set of secrets
an application accumulated — the source system tracked that in a `SecretNames`
slice on the application row that any failed deploy could leave incomplete
(`container.go:1152`).

Two things are settled by this entry.

**The method's contract is written down.** `DeleteScope` removes the named scope
and nothing else, is re-runnable, and refuses an empty scope with
`ErrInvalidSpec`. The last of those is the one that matters: an empty scope must
never be read as "every secret", which is the reading a substrate whose scopes
are a path prefix arrives at by doing nothing special.

This is a documentation amendment, not a behaviour change. All three
implementations — `compute/fake`, `compute/k8s`, `compute/aws` — already had
every one of these behaviours and nothing said so, which was verified by running
the new checks against all three unchanged before the doc comment was written.

**Two conformance checks enforce it**, with six defect fixtures in
`compute/aws/defects_test.go` showing each one failing against a deliberately
broken store and passing against the real one. A check that has never been shown
to fail is an assertion rather than a gate.

### A least-privilege posture for parameter reads, stated so it is not eroded

`aws.Provider.SecretReadPolicy` takes the workload's `SecretBinding`s and emits
the exact parameter ARNs, with `ssm:GetParameter` and `ssm:GetParameters` and
nothing else. `ssm:GetParametersByPath` and `ssm:DescribeParameters` are
excluded because enumeration over a hierarchy is a scope-shaped grant wearing a
resource-shaped one — a principal that can enumerate a path can read everything
under it. The source system grants exactly that:
`terraform/modules/ecs/iam.tf:43-46` allows reads on
`…:parameter{ssm_prefix}/apps/*`, so every application's tasks can read every
application's secrets.

**A scope-shaped variant is not offered, and adding one later is a decision
rather than a convenience.** The caller always has the binding set — it is
building the workload specification from the same slice — so the wider form buys
nothing, and an API that offers a wider grant beside a narrower one gets the
wider one used. Widening this needs an argument in a pull request, not a
parameter.
