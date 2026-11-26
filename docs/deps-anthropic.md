# Dependency review: anthropic

Reviewed 2026-11-21, before installing it. The official Python SDK for the Anthropic API. We use it for one thing: the
paid frontier agent (`AnthropicAgent` in `rlenvs/agents.py`, `python -m rlenvs frontier`) that measures each task's pass
rate with Claude Opus 5.5. Nothing else imports it: not the tasks, the verifier or the sidecars, and the local and
scripted agents run without it.

| Question | Answer | How I checked |
|---|---|---|
| What, which version | `anthropic` 2.6.0 on PyPI (uploaded 2026-11-05, a pure-Python `py3-none-any` wheel, Python >= 3.10). The latest, 2.12.0, was a day old at review, so it is not used: a pin at least two weeks old. 2.6.0 has `messages.stream` with `cache_control`, `output_config`, `thinking` and `tool_choice`, `stop_details` on a response and the `claude-opus-5-5` model id | PyPI JSON for `anthropic`; the installed package's signatures and types |
| Who maintains it | Anthropic: PyPI author "Anthropic <support@anthropic.com>"; source at `github.com/anthropics/anthropic-sdk-python`, the company's own organisation | PyPI metadata; GitHub API |
| How widely used | 4,090 stars, 913 forks, created 2023-01-17, pushed 2026-11-20, not archived; about 212 million PyPI downloads in the last month (51 million in the last week). A release every few days | GitHub API; pypistats.org |
| Licence | Apache-2.0 | PyPI metadata |
| Packaging | One wheel; no `.pth` file in the venv after installing it, so nothing runs at interpreter start; no console scripts. A wheel runs no code at install, and `uv pip install --no-build` refuses any package that would need a build step | `find .venv -name '*.pth'`; the dist-info has no `entry_points.txt` |
| What it pulls in | 8 required packages: `anyio`, `docstring-parser`, `httpx2`, `jiter`, `opentelemetry-api`, `pydantic`, `sniffio`, `typing-extensions`. `httpx2`, `anyio`, `pydantic` and `typing-extensions` were already in the venv (through mlx-lm and tracekit-ai); the install added `anthropic`, `docstring-parser`, `jiter` (a compiled Rust wheel for the JSON stream), `opentelemetry-api` (the API only, no exporter) and `sniffio`. Optional extras (`aiohttp`, `bedrock`, `vertex`, ...) are not installed | PyPI `requires_dist`; `uv pip install` output |
| What it can reach | **The network, only `https://api.anthropic.com`** (the client's `base_url`, which `anthropic_client()` fixes so an `ANTHROPIC_BASE_URL` in the environment can't redirect the key). Every other URL in the package is a documentation link in a docstring. No telemetry. **The key**: we pass it to the client explicitly; it is read at run time from `ANTHROPIC_API_KEY` or the macOS Keychain, dropped from the process environment so no child process inherits it, and never written to a log, result, ledger, transcript or run directory (`tests/test_frontier.py`). **Files**: none by itself | `grep` of every URL host in the package; `anthropic.Anthropic(...).base_url` |
| Install-time downloads | None from the SDK itself; the install fetches wheels from PyPI | install command below |

**Decision: install, in the project venv.** A first-party SDK from the API's own maker, an open licence and ordinary
packaging, and the dependencies are mostly already here. What an episode's agent code can reach is unchanged: the SDK
runs in the harness process, never in an episode's containers, and the model acts only through `Episode.call`.

```
uv pip install --python .venv/bin/python --no-build anthropic==2.6.0
```

Pinned in `requirements.txt`. Raise the pin only after a review of the release, a day-old one included.

## Installed (2026-11-21)

`anthropic` 2.6.0, `docstring-parser` 0.18.0, `jiter` 0.19.0, `opentelemetry-api` 1.45.2, `sniffio` 1.3.1 into `.venv`
(Python 3.11). Tests use a fake client; no API call was made while building it.
