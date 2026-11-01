# Vexor 2.7.2 local audit and release notes

## Scope and limits

This audit reviewed the local source checkout, launcher behavior, result routing,
persistence, and documentation consistency. It used offline unit/integration
fixtures and an isolated Python runtime. It did **not** use API keys, inspect `.env`,
run a paid generation, contact a model provider, or establish model-level security
behavior. The checkout has no `.git` directory, so change history and a source
rollback commit cannot be verified.

The release version is **2.7.2** in `main.py`, `run_toolkit.bat`,
`run_toolkit.sh`, and the README. Existing data formats remain additive/compatible.

## Startup incident diagnosis

The supplied startup log has two root causes:

1. `C:\Program Files\Python313\python.exe` cannot import standard-library
   `enum`. `venv` imports `shutil`, which imports `re`, which imports `enum`, so
   virtual-environment creation cannot succeed. This is a damaged or incomplete
   Python installation, not a missing Vexor dependency.
2. The previous Windows launcher continued after venv failure and used bare
   `pip`/`uvicorn` commands. Those stale launcher stubs referenced
   `C:\Python313\python.exe`, which does not exist. This produced misleading
   follow-on errors and attempted a server start without a usable environment.

### Launcher changes

`run_toolkit.bat` now:

- checks `VEXOR_PYTHON`, then `py -3.13` through `py -3.10`, then `python`;
- requires Python 3.10+ and successful imports of `enum`, `venv`, and `ensurepip`;
- fails before installing dependencies or starting the browser/server if none pass;
- rebuilds an incomplete/broken project venv;
- runs pip and Uvicorn only as `venv\Scripts\python.exe -m pip` and
  `venv\Scripts\python.exe -m uvicorn`;
- supports `--no-install`, `--no-reload`, and Windows-only `--restart`;
- does not use `certutil`, global `pip`, global `uvicorn`, or venv activation.

`run_toolkit.sh` provides the corresponding Unix behavior using `venv/bin/python`.
It does not claim Windows restart-loop support.

The Windows launcher was executed under `cmd.exe` against the currently broken
machine state. It returned exit code 1 with the intended repair guidance and did
not invoke pip, Uvicorn, or create a partial venv. A successful Windows bootstrap
cannot be tested until a complete Python interpreter is installed.

### Operator repair steps

1. Repair/reinstall Python 3.10+ from https://www.python.org/downloads/.
2. Open a **new** Command Prompt, verify:
   ```bat
   py -3.13 -c "import enum, venv, ensurepip; print('ok')"
   ```
   Use the installed version in place of `3.13` if needed.
3. From the project root, run `run_toolkit.bat --no-reload`.
4. If `PATH` is wrong but a complete interpreter exists:
   ```bat
   set "VEXOR_PYTHON=C:\full\path\to\python.exe"
   run_toolkit.bat --no-reload
   ```
5. Only after a clean install, use `--no-install` for offline/repeat starts.
   It intentionally fails if FastAPI/Uvicorn are not already installed in the
   project venv.

Do not point `VEXOR_PYTHON` at the isolated embeddable test runtime used during
this audit; it lacks `venv` and `ensurepip` by design.

## Configuration finding: provider credentials

The project-root `.env` was absent during the non-secret verification. A venv
startup test completed, but checks for `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`GOOGLE_API_KEY`, `XAI_API_KEY`, and `OLLAMA_API_KEY` were all false. No `.env`
contents or credentials were read.

`main.py` loads only `<project root>/.env`, before provider initialization, with
`override=True`. A key placed in a user profile directory, another project, or a
shell command using Command Prompt syntax in PowerShell will not configure this
application. Vexor expects `OPENAI_API_KEY` for OpenAI API access and
`ANTHROPIC_API_KEY` for Anthropic API access; `CHATGPT_API_KEY` is not a supported
variable. Restart the server after changing credentials, because initialized
provider clients do not hot-reload keys.

`.env.example` was corrected so placeholder assignments are commented out.
Previously copying it without replacing every placeholder could cause a fake value
to override a valid session environment variable. See the README configuration
section for non-secret verification commands.

## Code and reliability findings

| Finding | Status | Resolution / limitation |
|---|---|---|
| HTTP success was treated as model-test success even for returned error strings/refusals | Fixed | Provider outcome diagnostics distinguish completed, blocked, incomplete, empty, and error. |
| Policy refusal could be retried as parameter compatibility when wording mentioned a parameter | Fixed | Compatibility retry requires an unsupported-capability classification and stays on the same model. |
| Terminal responses could continue an automatic same-test sequence | Fixed | Blocked/error results stop the automatic sequence; no error-time cross-provider fallback is added. |
| Blocked-only results could look clean or enter discovery bookkeeping | Fixed | `not_evaluated`/partial coverage, checkpoint fields, report totals, mode summaries, and discovery/template exclusion added. |
| Scan checkpoint overwrote prior state directly | Fixed earlier | Atomic temporary-file replacement; failures are surfaced as sanitized warnings. |
| Route scan ID was joined into persistence paths without canonical UUID validation | Fixed | Persistence now validates canonical UUIDs, rejects traversal/noncanonical IDs, and checks persisted filename/JSON-ID agreement. |
| Batch/Unix launcher versions lagged application version | Fixed | Launchers and documentation now use 2.7.2. |
| FastAPI warmup task outlived app lifespan/reload | Fixed | Task is retained, cancelled, and awaited on shutdown. |
| `google-generativeai` SDK | Open | Installed runtime emits its upstream end-of-support warning. Current Google adapter still imports it; migrate deliberately to the supported Google SDK with mocked/live authorized compatibility tests rather than making an unverified API substitution. |
| Provider selection for scanner rate limiter/timeout independently guesses provider | Open | Needs a shared resolver; custom/dynamic routes can still have imperfect limiter attribution. |
| Queue wait is outside provider request timeout | Open | Overall queue-inclusive deadlines remain absent. |
| Some outer scan task aggregation/discovery warnings are coarse | Open | Terminal scan status is not proof that every intended probe was evaluated. |
| CSV/browser export and chain-history limits differ from full persisted evidence | Open | Preview metadata exists; export/context policy still needs a dedicated review. |
| Bundled server lacks authentication/TLS/multi-user isolation | Documented | It remains localhost-only by default. Public/network deployment requires separate reviewed controls. |

## Security and documentation updates

- `SECURITY.md` now identifies `127.0.0.1:8080` and explicitly warns that the
  bundled service has no auth, authorization, TLS, or multi-user isolation.
- README setup now explains the `enum` startup failure, `VEXOR_PYTHON`, launcher
  options, local verification, and 2.7.2 reliability scope.
- `FALLBACK_REVIEW.md` and `RELIABILITY_AUDIT.md` contain the local mocked
  routing/error matrix, evidence boundaries, configuration notes, and rollback
  guidance.

## Verification performed

```text
python -m unittest discover -s tests -p 'test_*.py' -q
Ran 91 tests ... OK

bash -n run_toolkit.sh
OK

Python compile pass
Compiled 64 Python files

Node vm.Script parse
Parsed 1 inline JavaScript block

import main
main import OK: 2.7.2
```

The test suite includes harmless mocked checks for refusals, timeouts, rate
limits, unavailable models, authentication, quotas, configuration, cancellation,
checkpoint recovery, path validation, and result coverage. The orchestration
benchmark is mock-only and must not be read as live-provider performance data.

## Rollback

No Git rollback point is available in this checkout. Before deploying 2.7.2,
archive the previous application source/configuration and separately back up
sensitive `data/` and `exploits/` directories according to local retention rules.
To roll back, stop the server and restore that matching source/configuration set;
do not use destructive reset commands or delete evaluation evidence. New fields
are additive; old results load as conservative `not_evaluated` records.
