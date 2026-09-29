# Notes: an AppHub example application

A small per-user notes service to deploy when you first try AppHub. It shows the
pieces a real application needs:

- **Data in DynamoDB.** AppHub provisions the table and passes its name as
  `TABLE_NAME`. The app reaches it with the task role through the default AWS
  credential chain, so there are no keys to configure.
- **Identity from the ingress.** AppHub's sign-in proxy puts the user's email in
  `X-Auth-Request-Email`. The app uses it to keep each user's notes separate and
  has no login of its own.
- **A web page and a JSON API**, one port, no build arguments, a non-root
  distroless image, and a clean exit on `SIGTERM`.

## Deploy it on AppHub

AppHub builds from the root of a GitHub repository, so this directory needs to
be the root of its own repository.

1. Copy this directory into a new GitHub repository under an account or
   organization where the AppHub GitHub App is installed:

   ```sh
   cp -R examples/notes ~/apphub-notes && cd ~/apphub-notes
   git init && git add . && git commit -m "Notes example"
   git remote add origin git@github.com:<owner>/apphub-notes.git
   git push -u origin main
   ```

2. In AppHub, create an application with:

   | Setting | Value |
   | --- | --- |
   | Source | `https://github.com/<owner>/apphub-notes`, ref `main`, Dockerfile `Dockerfile` |
   | Execution | Continuous service |
   | Container port | `8080` |
   | CPU / memory | the smallest size offered (256 / 512 is plenty) |
   | Replicas | `1` |
   | Database | Key-value (keep the default keys `pk` and `sk`) |
   | Exposure | Public with a hostname such as `notes`, or private |

3. Deploy it. When the deployment succeeds, open the address on the Domains
   tab. You sign in through AppHub's identity provider, then land on your notes.

No secrets are needed.

### Deploy it with the AppHub MCP server

An agent connected to AppHub's MCP server can do step 2 and 3. Call
`targets_list` to find a ready target that offers `key-value` databases, then:

```json
{
  "idempotencyKey": "create-apphub-notes-v1",
  "application": {
    "name": "Notes",
    "targetId": "<target id>",
    "source": { "url": "https://github.com/<owner>/apphub-notes", "ref": "main", "dockerfile": "Dockerfile" },
    "execution": "service",
    "port": 8080,
    "resources": { "cpu": 256, "memory": 512 },
    "replicas": 1,
    "exposure": { "mode": "public", "hostname": "notes" },
    "database": { "kind": "key-value" }
  }
}
```

Pass that to `applications_create`. Then call `deployments_create` with the
returned `id` and `revision`, and poll `deployments_get` until it is terminal.
The `resources` value must be one of the target's `resourceSizes`.

## What it reads from the environment

| Variable | Set by | Purpose |
| --- | --- | --- |
| `TABLE_NAME` | AppHub, when the app has a key-value database | The DynamoDB table. Required; the app exits with a message naming it if it is missing. |
| `LOCAL_DYNAMO_ENDPOINT` | you, locally | A DynamoDB Local URL. The app then uses dummy credentials and creates the table if it does not exist. Never set it on AppHub. |
| `DEV_USER_EMAIL` | you, locally | The user to act as when no sign-in header arrives. Refused unless `LOCAL_DYNAMO_ENDPOINT` is also set. |

The app listens on port 8080 on all interfaces. Logs are JSON on stdout.

## Data model

One table, keyed by the string attributes `pk` and `sk`, the defaults AppHub
gives a key-value table:

| `pk` | `sk` | Attributes |
| --- | --- | --- |
| `USER#<email>` | `NOTE#<id>` | `text`, `createdAt` |

Each user's notes share one partition, so listing them is a single `Query` and
needs no secondary index. AppHub does not create indexes, so this pattern
(put everything a request needs under one partition key) is the one to copy.
The note ID starts with zero-padded Unix nanoseconds, so sort-key order is
creation order and the newest notes come back first.

## HTTP interface

Every route needs the signed-in user; without one it returns 401. Browsers
sending a state-changing request from another site get 403.

| Route | Does |
| --- | --- |
| `GET /` | The notes page. |
| `POST /notes` | Form post that adds a note (`text`, up to 2000 characters). |
| `POST /notes/{id}/delete` | Form post that deletes a note. |
| `GET /api/notes` | `{"notes": [...]}`, newest first, up to 50. |
| `POST /api/notes` | Body `{"text": "..."}`. Returns the note with 201. |
| `DELETE /api/notes/{id}` | 204, or 404 if the note is not yours or does not exist. |

## Run it locally

With Docker:

```sh
docker compose up --build
```

Then open http://localhost:8080, where you are `dev@example.com`. Data lives in
memory and is gone when DynamoDB Local stops.

Without Docker for the app, against any DynamoDB Local listening on port 8000:

```sh
TABLE_NAME=notes LOCAL_DYNAMO_ENDPOINT=http://localhost:8000 \
  DEV_USER_EMAIL=dev@example.com go run .
```

Try the API as a different user by sending the header yourself:

```sh
curl -s localhost:8080/api/notes -H 'X-Auth-Request-Email: bob@example.com' \
  -H 'Content-Type: application/json' -d '{"text": "hello from bob"}'
```

## Test

```sh
go test ./...
```

The tests use an in-memory store in place of DynamoDB.
