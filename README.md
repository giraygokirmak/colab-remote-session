# Colab Remote MCP

Standalone Docker MCP server for temporary Google Colab CPU/T4 jobs. Agent code, dependency specifications, file outputs, and streamed kernel events travel over MCP. Google credentials never leave this server.

Use this server from OpenCode, Claude Code, or Codex to execute Python on an
ephemeral Colab runtime while keeping authorization and execution handles on the
server. Jobs return immediately; agents poll ordered stdout/stderr and kernel
events, then retrieve explicitly selected output files through MCP resources.
The server requests only the free standard CPU or T4 runtime. Google Colab
availability, quotas, and acceptable-use terms still apply.

**This project is independent; it is not a Google, Anthropic, OpenAI, or Codex
product.** It requires a Google account that can use Colab and the official
`google-colab-cli` PyPI package. No paid runtime or API-key service is used by
the MCP server.

## Requirements and capabilities

- Python 3.12 or 3.13 for local development; Docker for the documented deployment.
- Public OAuth clients using PKCE and Dynamic Client Registration. Access tokens
  are audience-bound to this server's `/mcp` endpoint.
- One encrypted file-keyring for Colab credentials; no host credential or
  environment-variable forwarding into agent code or MCP responses.
- Bounded streamed event history, client-owned resources, SHA-256-checked
  captured files, restart recovery, and explicitly reported best-effort cleanup.
- Only named public-index package requirement specifiers are accepted. User code
  itself is arbitrary remote Python and is **not** sandboxed by this service.

Start with [Docker quick start](#docker-quick-start), then connect your client
using its instructions below. There is no host `colab auth` step and no separate
MCP username/password login.

## One authorization interaction (not two auth commands)

The MCP `/authorize` endpoint is the wrapper for Colab authorization. It opens the completion page for the same connection, whose only action is **Open Google Colab authorization → approve → paste the code Google displays**. It does not ask for a separate MCP username/password or run `colab auth` afterward.

The installed-client credentials bundled by `google-colab-cli` do not permit a direct redirect to your MCP host. Consequently, Google's documented code-display page is retained. This is one user-facing Google Colab consent interaction; the manual paste step is a limitation of that client, not an extra login.

The server persists Colab's credentials in `keyring` service `google-colab-cli`, username `oauth_token`. The file-keyring encryption passphrase is independent, generated locally, and read once into an in-memory backend. A similarly named agent refresh token is never the Google refresh token. No endpoint or MCP tool returns the contents of the keyring.

### Trust/security model

- Deployment is for **one trusted Colab owner**. The MCP deployment does not offer multi-tenant Colab authorization, a revoke-My-Google button, or isolation between different Google accounts in one container. Protect the named volume and its passphrase file like any server-side OAuth credential.
- Each MCP OAuth client has a separate history namespace. The in-memory Google credential exchange prevents interactive-user `state` from referring to another connection. With an MCP bearer token, its jobs and files can be read; never paste tokens into prompts or run untrusted agents against your server.
- Colab code is **intentionally arbitrary Python in your Colab VM**. MCP is a compute broker, not a security sandbox. Secrets in the agent code itself are out of scope; the server never injects its own environment or credentials into source.
- Only explicit `client_exports` are downloaded into `/data/jobs/<job>/files`. Images/HTML kernel output are sent as separately typed MCP resource contents. Text/matrix/binary capture is capped (see code settings) and safe names/hashes always accompany entries.
- Google Drive mount can require a separate Colab/Drive side-channel consent. Do not claim `drive.mount()` was preauthorized by this Colab connection. It is not automatically proxied.
- You authorize running Colab code when you invoke `run_code`; the MCP server only allows the free Colab account's CPU or standard T4 and standard RAM.

## Docker quick start

Prerequisites: Docker with volume support and local browser access to the agent's
MCP callback as documented by your host. The following setup creates one named
volume for persistent credentials, state, and job results, plus a protected
passphrase file. The container does not need access to the host Docker socket.

The image runs as a non-root user. For the Compose configuration, also review
the read-only root filesystem, `tmpfs`, capability, and no-new-privileges
settings below before choosing a public deployment.

```sh
docker build --pull -t colab-remote-mcp:0.1.0 .
docker volume create colab-oauth-keyring

# Prepare the layout and a non-personal encryption passphrase. Do not use a Docker or personal Google token.
docker run --rm --user 0:0 -v colab-oauth-keyring:/data --entrypoint colab-remote-secrets colab-remote-mcp:0.1.0 generate /data/secrets
docker run --rm -d --name colab-init --entrypoint sleep colab-remote-mcp:0.1.0 600
docker cp colab-init:/data/secrets/keyring.password ./keyring.password
chmod 600 keyring.password
docker rm -f colab-init

# Preferred: stdin (your shell command may contain only the filename, not a key).
docker run --rm -it --name colab-remote-mcp \
  --mount type=volume,source=colab-oauth-keyring,target=/data \
  --mount type=bind,source="$PWD/keyring.password",target=/run/keyring.password,readonly \
  -p 127.0.0.1:8000:8000 colab-remote-mcp:0.1.0 \
  --public-url http://127.0.0.1:8000 --keyring-password-file /run/keyring.password
```

Alternatively, use `--keyring-password-stdin` inside an interactive container (`docker run -it`, without the bind). `--keyring-password` is a development/secret-manager fallback only; do not put it in shell history, compose, environment variables, or agent tool arguments.

For non-loopback access, put the single process behind TLS, configure the externally reachable HTTPS origin (no path) using `MCP_PUBLIC_URL=https://mcp.example.org`, and use the compose service as an example. Do not publish HTTP port 8000 directly. The authorization state is not bearer authentication and does not enable `/mcp`;
`/oauth/complete` accepts only a state issued to a known dynamic client, and its
pending Google authorization window expires after 30 minutes.

To test locally with MCP Inspector, create a self-signed certificate so RFC 8414 Dev defaults accept HTTPS; it is the user's responsibility to enable testing-only CA trust appropriately. Instructions below use the Docker Compose example, not Google production OAuth.

### Restarting

The encryption passphrase and `colab-oauth-keyring` volume must survive together. Stop/start/rebuild the same command without recreating either. If either is lost, MCP reconnect triggers the one real Colab flow again; there is no separate CLI action. Losing the MCP bearer cache also replays the same flow; no second auth service is involved.

## MCP clients

### OpenCode

Use the actual HTTP Streamable endpoint, including `/mcp`:

```sh
opencode mcp add colab --url http://127.0.0.1:8000/mcp
opencode mcp list
```

Open OpenCode, use `/mcps`, choose `colab`, and follow the Google Colab connection window. The client may open a browser. If it cannot exchange a loopback callback, check the OpenCode client-specific instructions and the tool version installed; no alternative Colab login command is implemented here.

### Claude Code

```sh
claude mcp add --transport http colab http://127.0.0.1:8000/mcp
# Inside Claude Code: /mcp -> select colab -> authenticate
```

Claude opens the wrapped Colab authorization. The paste-and-submit completion page eventually redirects back to the client's registered callback. Do not set an additional bearer token for this server.

### Codex CLI/IDE

```sh
codex mcp add colab --url http://127.0.0.1:8000/mcp
codex mcp login colab --no-browser
```

Open the printed URL in a browser, paste the full attempted callback URL into the terminal after the Google interaction finishes. `:8000/mcp` vs `:8000` matters. `codex mcp login` is the client's way to start this one flow, not an additional Colab authentication procedure. Current official documentation supports Streamable HTTP, OAuth Dynamic Client Registration, and refresh credentials; unsupported separately mounted modes are outside scope.

## Agent protocol (all output is safe to avoid logging secrets)

Client tools are on the MCP endpoint, not `/api` or a standalone REST runtime endpoint. Standard output messages become safe, sequence-numbered JSON events; `stderr` never includes unformatted exceptions/request headers.

1. `run_code(code, accelerator="cpu", idle_timeout_seconds=1800, requirements=None, client_exports=None)` returns **immediately** with the job ID and SSE-capable job state. Maximum `requirements` item count, bytes, and exports are limited by the module. The executing job is held in the background; poll `get_job_output`. One active job is allowed per single-owner server. `accelerator="cpu"` selects no accelerator; `gpu` selects `Variant.GPU`, `Accelerator.T4`, `Shape.STANDARD` only. No high-memory, A100, TPU, or paid entitlement is requested.
2. `get_job_output(job_id, after=0, limit=100, wait_seconds=15)` returns `{events, next_cursor, status, error?, cleanup?}`. `after` is the last successful event sequence (`0` = first). Use the returned cursor; don't retry an exhausted fixed page for liveness. `wait_seconds` long-polls for new events, then returns a still-running indicator. `stderr`, `stdout`, `display`, `artifact`, `status`, `error`, and clean-up events are separate. `display` HTML/Javascript is never resolved or executed by the server.
3. `cancel_job(job_id)` requests cancellation and triggers the same cleanup in `finally`. Cancellation cannot stop a synchronous remote network API from instantly aborting arbitrary Python C libraries, but cleanup waits within the configured backend deadlines and is reported when unassignment actually succeeds. It never reports a stale job as killed after losing remote contact.
4. `download_file(resource_uri)` for text or base64 `col.file://<job_id>/<filename>` returns a typed MCP content block with the actual bytes and hash. Prefer using MCP `ReadResource` on the provided resource template rather than downloading across the response repeatedly. `/contents` remote paths are never accepted as a source in the download tool. Only the local captured file directory is readable.

### Example task flow

```python
run_code(
  code='''import sys
print('running on Colab', sys.version_info[:3], flush=True)
# Runs on Colab; export only files written to /content/output.
from pathlib import Path
Path('/content/output/answer.txt').write_text('result\\n')
''',
  requirements=['numpy==2.4.2'],
  accelerator='gpu',
  client_exports=['/content/output/answer.txt'],
)
```

Packages are normally resolved against Colab's existing Python ABI, not versions copied from the MCP environment. Each `requirements` entry is passed as a **literal argv item** to `sys.executable -m pip install --no-input --disable-pip-version-check ... --` **on Colab**. Only named public-package requirement specifiers are accepted: pip options, direct URLs, local paths, direct references, VCS syntax and credential-bearing entries are rejected. The server provides no private-index configuration; ordinary pip public-index resolution and Colab's preinstalled packages apply. Using tools to reproduce a proprietary model for which you do not have entitlement remains your responsibility.

No interactive `input()` responses are forwarded: agent Python uses noninteractive execution and optional subprocesses. Google Drive mounting/input-injected code will intentionally time out; the code itself may report a prompt but no server-side stdin relay exposes remote credential entry to the agent. `matplotlib`, PIL, DataFrame HTML, rendered text/markdown, and ordinary stdout/stderr are captured within configured limits.

## Process model / cleanup

The executor does not shell out to host credentials, `docker`, or DNS providers. It imports `Client`, `SessionState`, `ColabRuntime`, and `ContentsClient` from `google-colab-cli` and requests exactly the remote CPU/T4 assignment. Remote bootstrap sources are sanitized constants/components plus the user's code JSON encoding. There is no host env injection and no global `~/.config/colab-cli` in the MCP process. Secrets live in own-keyring stores; `request` logs never contain bearer headers or runtime-proxy tokens.

Every assignment is tracked under a unique UUID with runtime callbacks, in memory; URLs/tokens are not serialized in files, events, or resource metadata. A tracked finalizer attempts `runtime.stop(shutdown_kernel=True)` and, independently, the official Colab backend `unassign(endpoint)`, then closes the local HTTP session. Download failures cannot skip either attempt. `unassigned=true` requires a successful `unassign` return; `runtime.stop()` alone never proves kernel death or remote release. Shutdown marks jobs for cancellation, releases local waiters and waits for tracked finalization. A forced process kill cannot complete remote cleanup, so restored active jobs are failed with an explicit unknown-release report rather than a false cleanup success.

CPU limits depend on Colab runtime details and ordinary agent-supplied work. The MCP timeout is an **idle message silence timer**, not a total CPU quota. Don't invent free tier quotas, run capacities, or data-provider support that the Google endpoint cannot grant.

## Development/verification

The current local verification run passes **39 tests**, Ruff checks, and Python
bytecode compilation. These are offline unit and loopback integration checks;
they do not certify a Docker build, Google authorization, or real Colab quota.

For the Compose deployment, complete the same volume and passphrase-generation
steps above, then uncomment its loopback port mapping and run `docker compose up
-d --build`. In a reverse-proxy deployment, change `--public-url` to the exact
external HTTPS origin and publish the service only through that trusted proxy.

```sh
python3.12 -m venv /tmp/colab-mcp-dev
/tmp/colab-mcp-dev/bin/pip install -e '.[dev]'
/tmp/colab-mcp-dev/bin/pytest
/tmp/colab-mcp-dev/bin/ruff check .
```

Tests mock Colab assignment/runtime/contents boundaries and use only isolated temporary file keyrings with synthetic token values. They never require Google credentials, host home files, real Colab sessions, Docker sockets, or cloud metadata. MCP SDK integration tests use a real Uvicorn listener on a randomized loopback port—not `httpx.ASGITransport`, whose buffered streaming response deadlocks this SDK sequence—and a socket guard rejects all other network calls. Coverage includes stdout/artifacts/integrity, cleanup and repeated cancellation, restart/torn-log recovery, two-client owner isolation, PKCE/resource audiences, token rotation/replay, CORS/body limits, keyring-only refresh, and lifespan shutdown. No live Google OAuth, Colab quota/execution, or Drive authorization is claimed: the operator must intentionally approve that separate real session.

## Data placement / operations

- `/data/secrets/keyring/crypted_pass.cfg`: encrypted Colab token.
- `/data/secrets/keyring.password` (created via generator, bind-mounted): passphrase only. This does not go into state.json or tool output.
- `/data/state.json`: MCP dynamic client registrations, pending state and SHA-256-hashed bearer credentials. Server-only 0600; no Google runtime URL/token or plaintext MCP bearer token.
- `/data/jobs/<random job ID>/job.json`: per-owner job status, event cursor and persisted event-prefix SHA-256 checkpoint; mode 0600.
- `/data/jobs/<random job ID>/events.jsonl`: bounded stdout/tracebacks/text display/reference events for restart recovery and cursor polling; not bare binary HTML to a browser.
- `/data/jobs/<random job ID>/files`: explicitly captured local Colab files and limited inline images; binary blob MCP resources.

Use regular backups if you care about output retention. Purging old jobs is a deliberate local administration operation and doesn't expose secrets via an MCP endpoint. For privacy disposal of keyring state, stop the server and remove/destroy its dedicated named volume plus protected passphrase, using your platform's standard secure deletion mechanisms. This product has no user-facing revoke tool because that would introduce a separate account lifecycle flow; revoke Google OAuth access via your Google Account > Security > Third-party apps if desired.

## Production guardrails

Single process (no multi-worker OAuth flows, no shared-in-memory lock across workers), only one active job, an explicit tunnel protecting public binding, no request-body JSON logging, no root shell in runtime image, read-only root filesystem, drop-all capabilities/no-new-privileges, no Docker/client socket mounted. Limit job size (128 KiB code, 32 KiB total dependency text, 64 MiB each/128 MiB per job files, 8 MiB text display) and enforce those at the source and polling layers. Resource reads are protected by client authorization, not only unguessable random job names.

## License

Copyright 2026 Colab Remote MCP contributors.

Licensed under the [Apache License, Version 2.0](LICENSE). You may not use this
project except in compliance with that license; it is provided on an “AS IS”
basis, without warranties or conditions of any kind. This project does not
relicense its Python dependencies, container base image, Google services, or
other third-party components.

MCP SDK version is pinned to 1.30.0, because this server implements the provider protocol and Streamable HTTP transport supported by that release. Auth metadata is SDK-generated; header parsing, `BearerAuthBackend` RFC 9728 resource matching, and no-store responses are not reimplemented ad hoc. The only custom HTTP auth paths implement the registered callback bridging limited installed-client interaction. A future direct HTTPS Google client is not compatible without adding its own Google Console config/scopes/verification.
