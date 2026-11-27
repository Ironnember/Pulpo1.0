# Opt-in offline Python profile candidate

Status: proposed, unreviewed, not activated by any existing launcher. The helper
is in the existing local-effect proof module; there is no new service, router,
executor, authority source or ledger.

## Problem and resulting behavior

The original profile limits writes and selected reads but permits other host
reads, network access and signalling. A synthetic read-allowlist candidate could
not start until it permitted read-data on the literal root directory and
metadata on known runtime/interpreter ancestors.

`build_offline_python_profile` exposes that tested configuration as a pure,
opt-in profile builder. It denies file reads/writes generally, permits selected
system/Python runtime reads, the exact worker script, scratch writes, root
directory read-data and directory-ancestor metadata, and denies networking and
signals. It retains ambient process/IPC defaults; it is not a deny-default
sandbox. Existing prepare/fire functions continue using their original builder.

Configuration is trusted input, not an agent proposal. The builder rejects
relative/missing paths, control characters, root-wide interpreter/workspace
scopes, workers resolving outside their workspace, interpreter/workspace
overlap and protected content overlapping allowed reads. Resolved names are
captured once and serialized without resolving symlinks again. These checks
validate topology, not the provenance or trustworthiness of interpreter code.

## Required change record

1. **Invariant:** a functioning synthetic offline worker should receive its
   selected stdin while being denied tested raw/unlisted/state/alias reads,
   state write-open, network routes, controller signalling and descendant reads.
   A profile that prevents startup is not a successful defense.
2. **Authority:** this helper starts no process, grants no permit and changes no
   current deployment. Its returned OS configuration is not authorization.
   Execution needs separately legitimate authority bound to the exact program,
   source, profile, input, working directory and current policy.
3. **Canonical state:** no canonical mutation is introduced. Synthetic tests
   create disposable `SQLiteKernelState` and files solely for access probes;
   they never open a live database. No new writer is exposed to the worker.
4. **Evidence:** configuration rejection tests run on all platforms. A real
   macOS test executes unconfined, restricted, root-subtree-mutant and
   intentionally injected-descriptor variants, with parent-observed signals,
   connections and workspace writes. It compares stdin/payload hashes and
   checks substitution of a hard-link alias onto the permitted code path,
   source/state preservation and cleanup. Non-Mac hosts explicitly skip
   this OS test. Exact run logs and candidate tree identity accompany review;
   historical 76/49-check harness results do not transfer to this revision.
5. **Limits:** no real model, provider, signing ceremony, deployed read-only
   transport or production acceptance is established. Extra descriptors passed
   by a trusted parent remain a demonstrated raw-data route. Ambient Mach/IPC,
   sysctl and process controls, resource exhaustion, arbitrary interpreter
   supply-chain changes and hostile-host behavior remain unproven. A separate
   deny-default profile still fails Python startup. Generated profiles with
   temporary paths are evidence, not installation files.
6. **Classification:** source/configuration behavior and executed synthetic
   checks can be Verified only at their recorded base/patch/tree and environment.
   Deployment suitability is Proposed; independent approval remains Unknown.
7. **Existing mechanism:** this extends the canonical sandbox module. It does
   not copy the domain executor into a generic document execution path or
   incorporate the separate response-projection kernel candidate.
8. **Temporal transfer:** the previous exact-main helper supplied the baseline
   deny-list behavior. No historical checkpoint with this read-allowlist contract
   exists. No general historical-transfer or future-authority import is claimed.

## Eight analytical passes

| Pass | Finding |
| --- | --- |
| Flip | A hostile child is probed for raw reads, signalling and alternate routes. |
| Reverse | Restrict raw capabilities before child access; do not rely on disclosure instructions. |
| Invert | Abort is failure; a green test witnessing a deliberate leak is a sensitivity control. |
| Inside-Out | Trusted setup still selects the interpreter and can inject descriptors. It cannot self-approve deployment. |
| Darken | Ambient IPC/process/sysctl capabilities remain beyond the proved file/network scope. |
| Lighten | The root directory allowance repairs observed startup without granting descendant content. |
| Amplify | A literal-to-subtree mutation must expose unlisted contents; tests must detect it. |
| Negate | Use fixed synthetic code and reviewed input; omit real credentials and model calls. |

## Reproduction and next gate

```bash
python3 -W error -m unittest tests.test_offline_python_profile -v
python3 -W error -m unittest discover -s tests -v
```

The Mac test requires actual `/usr/bin/sandbox-exec`. It performs only local,
synthetic operations and uses `-I -S` for its Python child. For detailed evidence,
the trusted test runner may set `PULPO_OFFLINE_PROOF_EVIDENCE` to an external
output filename; no model environment or authentication profile is inherited.

Before adopting a real launch path, an independently authenticated reviewer must
assess the exact configuration and source. The actual launcher must revalidate
program/source/profile/input identity, preserve closed extra descriptors, vet the
initial workspace and reauthorize at execution time. This candidate changes no
existing terminal profile or admission protection. The next gate is review and
completion of the still-unproven execution surfaces, not installation by default.
