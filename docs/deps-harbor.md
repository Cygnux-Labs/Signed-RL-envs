# Dependency review: Harbor

Reviewed 2026-11-17, before installing it. Harbor is the task format labs and resellers load; we install it only to
run our tasks the way a lab would (`harbor run`) and to check that the Harbor run is recorded and scored as our own
harness's is. It is not a dependency of the tasks or of the verifier: a lab brings its own Harbor.

| Question | Answer | How I checked |
|---|---|---|
| What, which version | `harbor` 0.25.0 on PyPI (uploaded 2026-10-25). The latest, 0.26.0, was 4 days old at review, so it is not used: a pin at least two weeks old | PyPI JSON for `harbor` and `harbor/0.25.0` |
| Who maintains it | Author Alex Shaw (Terminal-Bench's author); source at `github.com/harbor-framework/harbor`, an organisation repo (`laude-institute/harbor` redirects there) | PyPI metadata; `gh api repos/harbor-framework/harbor` |
| How widely used | 7,113 stars, 2,219 forks, 25 watchers, created 2025-08-04, pushed 2026-11-16, not archived. Releases since 2025-11-02, about every three weeks. The plan's research (Appendix A2) has Tinker, Prime's `verifiers` v1, OpenReward and several vendors loading Harbor tasks | GitHub API; PyPI release dates |
| Licence | Apache-2.0 (PyPI `license_expression`; GitHub `spdx_id`) | both |
| Packaging | One pure-Python wheel, `harbor-0.25.0-py3-none-any.whl`, 608 files, SHA-256 `51923ac5…c309`, which matches PyPI's digest. No `.pth` file, so nothing runs at interpreter start; a wheel runs no code at install. Entry points: the `harbor`, `hb` and `hr` commands only. Needs Python ≥ 3.12 | downloaded the wheel, `shasum`, `unzip -l`, read `entry_points.txt` |
| What it pulls in | 25 required packages, among them `litellm` (≥ 1.92.0), `supabase`, `fastapi`, `uvicorn`, `httpx`, `requests`, `pydantic`, `cryptography`, `pyjwt`, `jinja2`, `typer`, `rich`; about 35 optional extras (cloud sandboxes, Tinker, DSPy...), none installed here. litellm is the largest and has history: releases 1.82.7 and 1.82.8 are absent from PyPI; I recall them as the versions pulled after a reported supply-chain compromise in March 2026 (from memory, not re-checked); Harbor's floor of 1.92.0 is past them | PyPI `requires_dist`; litellm's PyPI JSON |
| What it can reach | **Docker** (it builds and runs task environments through `docker compose`). **The network**: (1) telemetry to PostHog, `us.i.posthog.com`, on by default, off with `HARBOR_TELEMETRY=0`, which every send path checks first (`harbor/telemetry.py` lines 321, 345, 366); (2) the dataset registry, `raw.githubusercontent.com/laude-institute/harbor/main/registry.json`, only for datasets named rather than given as a path; (3) Harbor Hub (`hub.harborframework.com`, a Supabase client) only on upload, publish or hosted-job commands; (4) model APIs through litellm only for agents that call a model. **Files**: the task directory, its own jobs directory, and the platform cache dir (`platformdirs`) | read `telemetry.py`, `constants.py`; every URL host in the package listed with `grep` |
| Install-time downloads | None from Harbor itself. The install fetches wheels from PyPI; `uv pip install --no-build` refuses any package that would need a build step, so no package's own code runs during install | install command below |

**Decision: install, isolated.** A known maintainer, an open licence and normal packaging. It goes in its own venv
inside the repo (`.venv-harbor`, Python 3.12, git-ignored), never in the project venv or the system. Every `harbor`
command here runs with `HARBOR_TELEMETRY=0` and a scratch `HOME` (the Makefile sets both), on local task paths only,
and with no model API keys in its environment.

```
uv venv --python 3.12 .venv-harbor
uv pip install --python .venv-harbor/bin/python --no-build harbor==0.25.0
```

## Installed (2026-11-17)

- `harbor` 0.25.0 and 91 dependencies (`litellm` 1.109.1 among them) in `.venv-harbor`, all wheels (`--no-build`); no
  `.pth` file in the venv. `tracekit-ai` 1.5.3 added there too (the same pin as the project), so the Harbor
  environment can reach the episode's signer.
- What it touched in use: Docker (colima's `rlenvs` VM) and the repo's `runs/` (jobs, a scratch HOME); no network
  beyond image builds, telemetry off.
- Docker here has no `buildx`, which Harbor's nftables egress sidecar needs to build; so `rlenvs.harbor_env` gives a
  no-network environment (the verifier's) Docker's `network_mode: none` from the start instead. Installing buildx
  would be its own dependency review.
- Task format findings from running it: `[task] authors` must be tables (`{ name = ... }`), and a `tests/Dockerfile`
  makes Harbor treat the tests as built into the verifier image (no upload), so the image copies them in.
