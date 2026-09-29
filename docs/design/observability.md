# Workspace log viewing

The admin Workspace's Logs tab reads CloudWatch Logs through
`internal/logs.Reader` (`serve`'s one deliberate exception to "a real cloud
credential lives only in the worker" -- see that package's doc comment for
why a log tail cannot wait for the durable worker-dispatch pattern used
everywhere else). What it can read is entirely operator-named: there is no
compiled-in list of containers, unlike some platforms that hardcode
`backend`/`frontend`/`traefik`/`oauth2-proxy`. AppHub itself only ever builds
two containers (`Dockerfile` for `serve`, which also embeds the built
frontend as static assets, and `worker.Dockerfile`), and any other component
in a deployment -- a reverse proxy, an SSO-enforcing auth proxy in front of
`serve`, anything else -- is infrastructure the operator runs, not something
this repository provisions or knows the name of ahead of time. So the log
viewer takes a list, not a convention.

## Configuring log groups

```yaml
observability:
  awsRegion: us-east-1
  logGroups:
    - name: serve
      logGroup: /ecs/my-apphub/serve
    - name: worker
      logGroup: /ecs/my-apphub/worker
    - name: traefik
      logGroup: /ecs/my-apphub/traefik
    - name: oauth-proxy
      logGroup: /ecs/my-apphub/oauth-proxy
```

- `name` is only a display label the Workspace's log-group selector shows and
  the `GET /api/v1/admin/logs/{name}` path uses to look up the group -- it is
  never a resource identifier this repository derives or checks against
  anything. Name your own containers whatever you already call them.
- `logGroup` is the exact CloudWatch log group name the container's `awslogs`
  log driver (or equivalent) writes to. AppHub does not create or manage this
  group; it must already exist and already be receiving that container's
  output.
- Add one entry per container or service you want visible in the Workspace,
  including ones AppHub itself does not run -- an external auth proxy (an
  `oauth2-proxy`-style deployment enforcing SSO in front of `serve`, distinct
  from AppHub's own embedded `internal/oauth` delegated-authorization server
  for CLI/MCP access) or a shared reverse proxy like Traefik are exactly the
  same kind of entry as `serve` or `worker`.
- The whole section is optional: omit it (or leave `logGroups` empty) and the
  Workspace's Logs tab reports nothing to show, rather than guessing a
  default. `awsRegion` and a nonempty `logGroups` are required together --
  see `serverconfig.validateObservability`.

## IAM

`serve`'s task role needs exactly `logs:FilterLogEvents` (and, if you want the
Workspace to be able to enumerate streams within a group later,
`logs:DescribeLogGroups`) scoped to the log groups named above -- nothing
else. `internal/logs` does not choose or enforce that policy; it only uses
whatever credentials the process's ambient chain provides, the same
`config.LoadDefaultConfig` chain `compute/aws` uses. In particular `serve`
does not need, and should not be granted, any permission to write to or
delete a log group: the Workspace only ever reads.

## Using it

Once configured, an administrator opens **Workspace → Logs**, picks a log
group by its display name, a time range (15 minutes to 24 hours, or a custom
RFC 3339 window via the API), and an optional CloudWatch filter pattern
(passed through unmodified -- CloudWatch's own syntax, not a search this
repository interprets). The view auto-refreshes every ten seconds while a
group is selected.
