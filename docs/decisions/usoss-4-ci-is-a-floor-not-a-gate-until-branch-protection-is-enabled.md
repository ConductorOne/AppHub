## USOSS-4 — CI is a floor, not a gate, until branch protection is enabled

**Do not read a green check as a guarantee.**

This repository has a set of CI jobs, a CODEOWNERS file, and a set of import,
disclosure, and hermeticity gates. None of them is currently *required*.
`main` has no branch protection and no ruleset, so a direct push bypasses every
workflow and every owner, and CODEOWNERS additionally names a team that does not
exist yet. Both are organisation-level settings that cannot be created from
inside a pull request, and both are escalated.

Until they are in place, the honest description of the quality bar is: the gates
tell a contributor who runs `make check` whether their change is sound, and they
tell a reviewer the same thing on a pull request. They do not *prevent*
anything. Nobody should describe this repository as having an unskippable floor,
in a README or anywhere else, before the following exist:

- branch protection (or a ruleset) on `main`;
- every CI job required to pass;
- code-owner review required, against a team that exists and has write access;
- force pushes and direct pushes to `main` disallowed;
- the DCO check required. The check itself now exists and runs on every pull
  request (`make dco`), but like every other job it is advisory until something
  requires it.

This entry exists so that the gap is written down where somebody evaluating the
project will find it, rather than inferred from the absence of a setting.
