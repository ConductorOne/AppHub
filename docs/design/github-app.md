# Registering AppHub's GitHub App

The Workspace GitHub App is the deploy allowlist. Configure it in the
AppHub UI after the stack is up; Terraform does not need a list of
repository URLs. An optional operator `source.repositories` list remains an
extra restrictor for deployments that want one.

`internal/githubapp` mints installation tokens. The worker (`Checkout`,
`Detector`, `GitHubSyncer`) is the only process that holds the App private
key. This document is how that App gets registered and installed.

## Why a GitHub App, not a personal access token

A private repository needs read access without handing AppHub a human's
broad, long-lived credentials. A GitHub App scoped to `contents: read` on
exactly the repositories it is installed against, minting short-lived (≤1h)
installation tokens on demand, is the least-privilege way to do that.
AppHub never requests or stores a personal access token for source access.

## What the App is used for

- **Allowlist** (`internal/controlplane`): when `source.repositories` is
  empty, a deploy or detection URL is allowed only if a synced,
  non-suspended installation's account owns that repository.
- **Deploys** (`internal/source.Checkout.Prepare`, run by `apphub worker`):
  clones the exact commit an accepted deployment names, to build its
  container image. The worker looks up the installation for the repository
  owner and mints a token scoped to that one repository.
- **"Simple deploy" repository detection** (`internal/source.Checkout.Discover`
  and `internal/worker.Detector`): the same shallow clone, before an
  application exists, to suggest a Dockerfile path, its `EXPOSE` port, a
  `docker-compose` preview, and a database guess. See
  `internal/detect`'s package doc.

Both clone paths run only in `apphub worker`. `apphub serve` — the process
that terminates a requester's HTTP connection — never loads a GitHub App
private key at all (`internal/ghappkey` hands serve a write-only store). It
only ever sees the App ID and the installation records the worker synced.
That split is deliberate: whichever process can be reached from outside must
never hold the key.

## 1. Register the App from Workspace

In AppHub, open **Workspace → GitHub App** and complete the manifest flow
(or paste an existing App ID and private key). `cmd/apphub` derives the SSM
parameter path from the DynamoDB table name; there is no Terraform variable
for the key. The manifest does not turn the webhook on, and GitHub's
generated webhook secret is discarded.

On the App's settings page, check **Webhook → Active**. The URL is
`{publicOrigin}/api/v1/github/webhook` (`terraform output github_webhook`).
The secret is the Parameter Store value named there, injected into the API
container as `APPHUB_GITHUB_WEBHOOK_SECRET`. Read it with
`aws ssm get-parameter --with-decryption` and paste that string into GitHub;
do not base64-decode it. Content type is `application/json`. `serve` checks
`X-Hub-Signature-256` over the raw body and rejects any delivery that does
not match. A verified delivery is acknowledged and is not applied to
installation records; the worker still syncs those.

If you register the App in GitHub's own UI instead:

- **Repository permissions → Contents**: **Read-only**. This is the only
  permission the deploy and detection paths use
  (`internal/source.authentication` requests exactly `{"contents": "read"}`).
- **Where can this GitHub App be installed?**: "Only on this account" unless
  you specifically intend to let other accounts install it.

## 2. Install the App on the accounts it needs

From the App's settings page, **Install App**, choose the organization or
user, and select the repositories AppHub will deploy from — either a
selected set or all repositories on that account. GitHub's installation is
the allowlist: a repository the installation cannot reach will fail when
the worker mints a token, even if the API already accepted the owner.

The worker syncs installations every five minutes into durable records the
API reads. A brand-new install is not deployable until that sync lands.

## 3. Optional operator `source.repositories`

A non-empty `source.repositories` list is still an extra restrictor: the
API refuses any URL that is not listed, even if the GitHub App is
installed on that owner. Each `auth: githubApp` entry can also name its
own App ID, installation ID, and worker-only private key for clone auth
instead of the Workspace App.

```yaml
source:
  repositories:
    - url: https://github.com/your-org/your-private-app
      auth: githubApp
      githubApp:
        appId: 123456
        installationId: 78901234
        privateKeyFile: /etc/apphub/github-app.pem
```

Empty (the Terraform default) means skip this list entirely.

## 4. Rotating or revoking

GitHub allows multiple active private keys per App simultaneously, so a
rotation is: generate a new key, upload it in Workspace, confirm a deploy
or a detection scan succeeds, then delete the old key from the App's
settings page. Uninstalling the App (or removing a repository from its
installation) revokes GitHub's side immediately; any installation token
already minted still works until its own short expiry, which is GitHub's
own upper bound of one hour
(`internal/githubapp.App.MintInstallationToken`).
