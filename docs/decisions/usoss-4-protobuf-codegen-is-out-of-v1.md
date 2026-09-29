## USOSS-4 — Protobuf codegen is out of v1

The source repository generates Go from `backend/api/proto` via `buf`
(`Makefile:200-208`, plus `proto-lint` and `proto-breaking`). AppHub does not
carry it in v1.

The proto surface describes the internal source **service API** — its RPC
boundary with its own frontend and callers. What is being extracted is the
application ecosystem underneath that API: the modules, the compute providers,
and the credential layer. None of them need the wire format, and none of the v1
tickets port a server that serves it.

Bringing it along would mean vendoring a `buf` toolchain, pinning a plugin set,
and adding generated code to a public repository — a build dependency and a
review surface bought for a boundary this repository does not have. If AppHub
later grows a service API of its own, that API should be designed for AppHub
rather than inherited from the shape of an internal one.

Consequence: no `buf.yaml`, no `buf.gen.yaml`, no `api/proto`, and no
`make proto` target. Adding them later is additive and cheap; carrying them now
is not.
