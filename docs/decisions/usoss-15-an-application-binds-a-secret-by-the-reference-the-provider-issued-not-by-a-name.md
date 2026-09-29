## USOSS-15 — an application binds a secret by the reference the provider issued, not by a name

`Application` carried `SecretNames []string`, documented as names of secrets
already held by the provider under the application's scope. Review showed the
execution path could not resolve one: a caller could supply exactly the
documented input and the deploy would fail at binding time, after the identity,
the repository and the image had been created.

### Why a name could not work

`compute.SecretStore` has `Put`, `Get`, `Delete` and `DeleteScope`. `Get`
already needs the `Ref`. Nothing turns a scope and a name into one.

The binder's table of names was seeded from `Artifacts.Secrets` — the references
*this module* recorded on previous deploys — so a name only resolved for a
secret this module had itself stored. A secret stored by anything else, which is
what the field documented, never resolved. The positive test passed only because
it copied a provider-issued reference into the artifact map by hand, which is
record output rather than the documented input.

### The change

`Application.Secrets []SecretBinding`, where a binding is an environment
variable name and a provider-issued `compute.Ref`. A reference is resolvable by
construction, and — the part that matters for the ordering contract — everything
about it that can be established *without reading credential material* is
established before anything is created:

* it is non-zero;
* it names a secret rather than some other kind of resource;
* it was issued by the provider this deploy is against, which is
  `ErrForeignRef` said before the provider gets the chance to say it;
* no two bindings claim one variable, and none claims a variable this module
  sets itself — derived from the plan, so a resource added later brings its
  variables into the check without a second list.

### What this does not do, and the follow-up

It does not make a *name* work. Somebody holding a name and not a reference —
which is the friendlier input — still needs a provider-side lookup, and that is
an interface question rather than this module's to invent. Filed as a follow-up
along with the adjacent gap: existence is not checkable either, because the only
read operation returns the value, so a reference to a deleted secret is still
refused by the provider mid-deploy. A test pins that as the current behaviour so
a later `Describe`-style operation turns it red rather than quietly improving
the guarantee.
