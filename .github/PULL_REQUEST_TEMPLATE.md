## What this changes

<!-- One paragraph. What does the tree do after this that it did not do before? -->

Ticket: <!-- USOSS-N, or "none" -->

## What I deliberately did NOT do, and why

<!-- The most useful section in this template. Scope you left out, a port you
     stopped short of, a shortcut you took knowingly, an interface concession
     you had to make. "Nothing" is a valid answer, but think before writing it. -->

## How this was tested

<!-- Commands you actually ran and what they printed. If something is untested,
     say which part and why. A truthful partial result is worth more than a
     confident claim that does not survive review. -->

```
$ make check
```

## Checklist

- [ ] Every commit is signed off (`git commit -s`) — DCO, not a CLA
- [ ] `make check` passes locally
- [ ] Tests are hermetic: no network, no cloud credentials, no ConductorOne
      account, no fixed ports
- [ ] No account ID, ARN, key, token, internal hostname, VPC/subnet/SG ID, or
      other site-specific identifier is committed — anything like that became
      configuration with no default
- [ ] No package outside `credentials/c1` gained a ConductorOne dependency —
      direct, transitive, or behind a build tag (`make boundary`)
- [ ] No package outside `store/` gained a DynamoDB dependency (`make boundary`)
- [ ] New `.go` files carry the Apache-2.0 SPDX header
- [ ] No new claim that persistence is cloud-agnostic — v1 is DynamoDB, fenced
- [ ] Any gate this PR adds or changes has a fixture that **fails before the
      change and passes after** — a gate nobody has tried to defeat has an
      unknown detection rate
- [ ] Docs updated if behaviour or setup changed

## Anything a reviewer should look at hard

<!-- Assumptions you made, a design you are unsure about, a security-relevant
     decision, or a problem you found in the source you ported from. -->
