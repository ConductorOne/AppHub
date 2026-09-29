## USOSS-7 — OpenAI credential provider is not ported in this package port

`backend/internal/credentials/openai.go` is **not ported** by USOSS-7. The ticket's package port brings over the credential contract, the registry, Datadog's static vendor-key provider, and GitHub App installation-token minting. It does not add a third commercial provider in the same change.

The source OpenAI provider is a direct OpenAI Admin API service-account adapter: it reads `admin_api_key` and `project_id` from request metadata, creates a project service account at `https://api.openai.com/v1/organization/projects/{project}/service_accounts`, returns the one-time API key value, and deletes or checks that same service-account resource later. That is provider-specific product integration, not interface or registry surface. Adding it later is a separate provider ticket, with its own review of scope, admin-key handling, expiry semantics, response-body hygiene, redirect policy, and tests.

Three boundaries are therefore fixed for this port:

* `credentials/datadog` and `credentials/github` are the USOSS-7 cloud-neutral providers in this repository; `credentials/openai` does not exist and no provider registers ID `openai`.
* The absence of OpenAI must not narrow the credential interface. A future OpenAI provider still fits the existing `CredentialProvider` contract: static issuance, revocation, and provider status, with provider-specific metadata validated inside the provider.
* A future implementation must use the same constructions established by this port for credential-bearing HTTP: `internal/credhttp` owns redirect refusal and transport-error classification, response bodies are not rendered into errors, and tests stay hermetic with no OpenAI credentials or network.

This records scope, not a permanent product rejection. It prevents the current non-port from becoming an implicit interface simplification or a silent obligation to stub an OpenAI package without the security review a provider deserves.
