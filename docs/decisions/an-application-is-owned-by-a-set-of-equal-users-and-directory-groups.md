## An application is owned by a set of equal users and directory groups

An application has between 1 and 20 owners. Each owner is an AppHub user or a
synced directory group (a `DirectoryEntitlementKind` ID). Everyone holding a
group owns the application, and Eligibility re-checks that membership on every
request and when a worker executes an operation, the same way it resolves
roles. So leaving a group ends ownership without anyone editing the
application.

All owners are equal. Each can open, edit, deploy, manage secrets and delete
the application, and each can add or remove owners, themselves included.
Administrators can do the same without being owners. The last owner cannot be
removed.

### How it is stored

* `ApplicationRecord.Owners` is the authoritative set, and it replaces
  `ownerUserId`. A row written before owner sets existed is read as a one-user
  set (`ApplicationRecord.UnmarshalJSON`). Nothing writes `ownerUserId` any
  more.
* Each owner also has an `ApplicationOwnerKind` index record, committed in the
  same transaction as every change to the set. This keeps "the applications I
  own" an indexed query per owner key (the user, plus each group the user
  holds) rather than a walk of every application. The worker's
  `OwnershipIndexer` files the entries that legacy rows lack, and repairs any
  that go missing.
* An ownership change does not bump the application revision, so it never
  conflicts with a queued deployment. It is refused while an operation holds
  the application, because the worker rewrites the application record under
  compare-and-swap and a concurrent write would fence it.

### Alternatives refused

* **A primary owner with lesser co-owners.** It adds a transfer flow and a
  second permission tier, to protect against something the last-owner rule
  and administrators already cover.
* **Owners only on the application, with the listing filtering every
  application.** It is a table walk on a hot path, which the repository port
  forbids.
* **Pending owners by email.** A person who has never signed in has no user
  record to own with. A directory group already covers "people who will join
  later".
