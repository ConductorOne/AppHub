## USOSS-4 — this repository does not vendor dependencies

`/vendor/` is gitignored and no vendor tree is tracked. That is a decision, not
an accident, and it is load-bearing for the import boundary.

The file half of the boundary check skips `vendor` the same way it skips
`testdata`, on the reasoning that a vendored package is a dependency rather than
repository source. Review demonstrated the consequence: a complete tracked
vendor tree with a custom-tagged file inside a vendored package can carry a
forbidden import that the file scan never reads. Exploiting it needs a
conspicuous commit that contradicts this decision, so it is not a hole today —
but it becomes one the day vendoring is adopted.

**Before this repository ever vendors dependencies**, one of the following had
to happen first:

- the boundary checker fails outright when a tracked vendor tree exists; or
- the scan covers `vendor/` under a policy designed for it — which has to reckon
  with third-party code legitimately carrying constraints this repository's
  support matrix does not run.

**USOSS-28 took the first option.** `make boundary` now fails if a `vendor`
directory exists at the module root, before it judges anything, and says why: with
a vendor tree present `go build` compiles the vendored copy while the checker
resolves modules through the module cache, so the graph being proved about is not
the graph being built. Adopting vendoring therefore means writing the vendor mode
first — the check will not quietly let it through.

**USOSS-31 leaves the store idiom allowlist alone for the same reason.** The
idiom rule allows module-relative `store/`, plus the two DynamoDB provisioning
adapter files. If vendoring is ever adopted, dependency source under `/vendor/`
has to be classified before that rule runs: `vendor/example.com/x/store/...` is
not this repository's `store/`, and a third-party package that legitimately knows
DynamoDB must not be turned into a first-party store-fence violation. Widening
`AllowedPrefixes` to include `vendor/` today would be worse than the false
positive it tries to avoid, because there is no supported vendor mode and a
directory such as `cmd/vendor` is still first-party source. Vendor-mode work must
therefore revisit the idiom source set and this allowlist together; the current
no-vendor state has no live store-idiom bug.
