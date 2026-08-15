# First Autonomous Build Slice F1 — Kimi Owner Login Ceremony Preparation

```text
F1_KIMI_LOGIN_CEREMONY_IMPLEMENTATION=QUALIFIED
F1_KIMI_LOGIN_CEREMONY_STATE=OWNER_ACTION_REQUIRED
F1_KIMI_LOGIN_STATUS=NOT_YET_EVALUATED
FIRST_AUTONOMOUS_BUILD_COMPLETE=NO
```

This checkpoint prepares the owner-only authentication ceremony for the exact
official Kimi Code CLI 0.36.1 runtime. It does not perform login, OAuth/device
authorization, credential-content access, a model prompt, inference, Kimi
Builder work, scheduler integration, F2, G2, or G1.

## 1. Starting baseline

The verified common Windows, WSL, fetched `origin/main`, and independently
observed GitHub `refs/heads/main` baseline was:

```text
4cecd66b945a72265946d50be7703b2a8f978969
```

Both authoritative clones were clean on `main` at divergence `0/0`; both
stash lists were empty. The pre-ceremony census found no qualified Kimi
credential root, Kimi process, Kimi-related socket, API-key environment name,
or owner-login scope.

## 2. Exact runtime and immutable policy

The wrapper revalidates the qualified Kimi Code CLI 0.36.1 executable at
`/home/brand/.local/share/agenticos/provider-qualification/kimi-code/0.36.1/runtime/bin/kimi`.
Its required SHA-256 remains
`78c07b255e0bdc8dfe90d0cbd3204a3d862957394a08ca99c6e31144732451c7`.
It also revalidates the pinned qualification bundle, exact reported version,
immutable config and Planner profile, executable owner/mode, and pinned
Bubblewrap identity before the login process can start. There is no PATH,
version, provider, API-key, or configuration fallback.

The owner wrapper binds itself to one supplied 40-hex commit and requires the
WSL checkout to be clean `main` with both `HEAD` and `origin/main` equal to
that commit.

## 3. Credential root

Only after all synthetic ceremony tests and adversarial review were green,
the approved external state root was created at
`/home/brand/.local/share/agenticos/provider-state/kimi-code/0.36.1`.
The state root and its `credentials/` child are owned by WSL uid 1000, mode
`0700`, and structurally `EMPTY`. No fake final credential and no transient
credential file was created.

The wrapper revalidates the no-symlink ancestry, the owner and mode of every
owner-controlled parent, the state root and credential directory identities,
allowed names, entry types, owner/mode/link rules, and absence of unknown or
lingering transient entries. It opens the credential directory once with
`O_PATH|O_DIRECTORY|O_NOFOLLOW`; Bubblewrap mounts that kernel object through
`--bind-fd`, preventing a later path re-resolution from switching the mount.
AgenticOS does not open, read, hash, copy, deserialize, or record credential
file content.

## 4. Owner-only login runtime

The returned command creates the exact systemd user scope
`aos-kimi-owner-login.scope` with control-group kill semantics and bounded
tasks, memory, and stop time. The wrapper requires stdin, stdout, and stderr to
be real terminals and inherits all three directly without pipes, capture,
`tee`, or transcript storage.

Bubblewrap creates new user, PID, mount, network, IPC, UTS, and cgroup
namespaces; an empty `/workspace`; sterile home and Kimi roots; read-only
pinned executable/config/profile mounts; and only the approved credential
submount as persistent writable authority. The namespace launcher can express
only the exact `execve` vector `kimi-code login` for the official pinned
executable. It receives no prompt, project checkout, controller state, API
key, model endpoint authority, or alternate command.

On completion, cancellation, policy failure, or cleanup error, the wrapper
terminates and recursively drains the entire process group. The systemd scope
provides an independent cgroup-level drain boundary.

## 5. Opaque authentication relay

The Kimi client has no external route. It receives one loopback HTTPS proxy
inside its private network namespace. The listening socket is transferred to
the outer relay by one validated `SCM_RIGHTS` handoff; this does not confer a
general network-namespace handle.

The relay admits only exact CONNECT authority `auth.kimi.com:443`. It parses
the plaintext CONNECT metadata and the initial TLS ClientHello metadata needed
to prove exact visible SNI `auth.kimi.com`, then forwards TLS records unchanged.
It never terminates provider TLS and never parses or records OAuth HTTP bodies,
authorization codes, tokens, verification URLs, device codes, or encrypted
request/response content.

Each connection performs a fresh one-shot DNS resolution of the authorized
hostname, applies the qualified all-address/special-address policy, and makes
only a numeric connection to the validated result. IP literals, missing or
malformed SNI, hostname/SNI disagreement, unsupported ECH/hidden SNI, a second
ClientHello, HelloRetryRequest, TLS version ambiguity, alternate names, and
unknown destinations fail closed.

HTTP redirects remain inside encrypted TLS and are neither inspected nor
authorized by the relay. Any redirect follow-up connection independently
repeats CONNECT, SNI, DNS, and address-policy validation. A redirect to another
hostname therefore fails at the next connection.

`api.kimi.com:443`, `code.kimi.com:443`, and every other destination remain
denied. The wrapper reports only an unauthorized hostname and content-free
reason code; it never widens the allowlist automatically.

## 6. Synthetic qualification

The ceremony-specific unit/native corpus proves exact-host admission; wrong
CONNECT host; wrong, missing, malformed, and hidden SNI; IP-literal denial;
alternate-host redirect follow-up denial; second-ClientHello and
HelloRetryRequest denial; `api.kimi.com`, `code.kimi.com`, and arbitrary-host
denial; immutable-pin failure; credential-root failure; real-terminal
requirements; listener handoff; direct terminal I/O; exact login-only exec;
namespace/mount isolation; and recursive cancellation/drain behavior.

The native Bubblewrap fixture creates the real private network namespace and
listener-FD handoff, attempts only synthetic `api.kimi.com` proxy traffic,
receives a denial, never executes the synthetic replacement Kimi program, and
leaves its temporary credential directory empty. The existing qualified M4B
regressions supply synthetic DNS, prohibited-address, ClientHello, SNI, TLS,
and second-handshake coverage without real provider traffic.

Final qualification results:

```text
CEREMONY_UNIT_AND_NATIVE_TESTS=42_PASSED
FOCUSED_SECURITY_AND_DEMO0_REGRESSION=PASSED
FULL_NATIVE_WSL_SUITE=2663_PASSED_2_SKIPPED
PYTHON_COMPILEALL=PASSED
REAL_KIMI_LOGIN_EXECUTED=NO
REAL_KIMI_PROMPT_EXECUTED=NO
REAL_KIMI_INFERENCE_EXECUTED=NO
```

## 7. Adversarial review

The implementation review found and resolved:

1. a fail-open indentation error in exact scope validation;
2. an invalid `systemd-run --scope --wait` combination;
3. credential mount path re-resolution after validation;
4. missing creation and validation of the private parent directory chain;
5. loss of the observed wrong-SNI hostname in content-free evidence;
6. acceptance of malformed post-handshake TLS record metadata;
7. a listener left reachable after its connection limit;
8. process drain skipped when relay cleanup raised;
9. residual descendants after direct-parent exit;
10. low-level runtime detail escaping the safe wrapper error code; and
11. a late-accept relay shutdown window.

Each finding was repaired with focused regression coverage or by strengthening
an already-covered lifecycle invariant. Final review verdict:

```text
F1_KIMI_LOGIN_CEREMONY_ADVERSARIAL_REVIEW=GO
UNRESOLVED_CRITICAL=0
UNRESOLVED_IMPORTANT=0
```

## 8. Remaining boundary and hard stop

The owner-facing browser/device interaction is outside AgenticOS and remains
owner-controlled. AgenticOS brokers only the pinned Kimi CLI authentication
connection. The real endpoint behavior, owner membership result, credential
leaf creation, and post-login structural/authentication status are not yet
observed and are not claimed qualified by this preparation checkpoint.

The exact owner command is emitted only in the post-publication report because
it binds the immutable published commit SHA. The agent must not execute it.
After publication, the only next action is the owner's personal ceremony.

```text
F1_KIMI_LOGIN_CEREMONY_STATE=OWNER_ACTION_REQUIRED
```
