# Run every target from this directory. Docker runs in the colima VM (RLENV_DOCKER_CONTEXT, default colima-rlenvs:
# `colima start rlenvs --cpu 4 --memory 4`).
PY := $(CURDIR)/.venv/bin/python
TASKS := $(sort $(patsubst tasks/%/task.toml,%,$(wildcard tasks/*/task.toml)))
TASK ?= rotate-the-credential-hard
MODEL ?= mlx-community/Qwen3.5-4B-MLX-4bit
N ?= 3
FRONTIER_MODEL ?= claude-opus-5-5
FRONTIER_N ?= 8
DOCKER := docker --context $(or $(RLENV_DOCKER_CONTEXT),colima-rlenvs)
# Harbor runs: its own venv (docs/deps-harbor.md), no telemetry, a scratch HOME, docker's config where it is
SCRATCH := $(CURDIR)/runs/harbor-home
HARBOR_ENV := HOME=$(SCRATCH) TRACEKIT_RUNTIME_DIR=$(SCRATCH)/run HARBOR_TELEMETRY=0 DOCKER_CONFIG=$(HOME)/.docker \
	DOCKER_CONTEXT=$(or $(RLENV_DOCKER_CONTEXT),colima-rlenvs) PYTHONPATH=$(CURDIR)

.PHONY: sync keys test gate gates calibrate need-cap frontier harbor-gate

# each task directory is self-contained (Harbor copies only it): the shared sidecars and verifier are copied in
sync:
	for t in $(TASKS); do \
	  mkdir -p tasks/$$t/environment/signer/keys tasks/$$t/environment/door/serve tasks/$$t/environment/fence; \
	  cp sidecars/signer/Dockerfile sidecars/signer/.dockerignore sidecars/signer/entrypoint.py sidecars/signer/policy.yaml \
	    tasks/$$t/environment/signer/; \
	  cp sidecars/signer/keys/.gitignore tasks/$$t/environment/signer/keys/; \
	  cp sidecars/door/Dockerfile sidecars/door/.dockerignore sidecars/door/door.py rlenvs/scan.py tasks/$$t/environment/door/; \
	  cp sidecars/door/serve/.keep tasks/$$t/environment/door/serve/; \
	  cp sidecars/fence/Dockerfile sidecars/fence/fence.sh tasks/$$t/environment/fence/; \
	  cp sidecars/main/files.py tasks/$$t/environment/files.py; \
	  cp verifier/Dockerfile verifier/.dockerignore verifier/test.sh verifier/rlscore.py rlenvs/scan.py tasks/$$t/tests/; \
	done

# a per-build log key for each task's signer (git-ignored, made once) and the trust.json its verifier pins
keys: sync
	for t in $(TASKS); do \
	  k=tasks/$$t/environment/signer/keys/log.key; \
	  [ -f $$k ] || $(PY) -I -c "import os, sys; os.umask(0o077); open(sys.argv[1], 'wb').write(os.urandom(32))" $$k || exit 1; \
	  $(DOCKER) build -q -t cygnux-rlenv-signer:$$t tasks/$$t/environment/signer >/dev/null || exit 1; \
	  $(DOCKER) run --rm --network none --entrypoint python cygnux-rlenv-signer:$$t -I /etc/rlenv/entrypoint.py \
	    --print-trust > tasks/$$t/tests/trust.json || exit 1; \
	done

test:
	$(PY) -m pytest -q

# the honest solution must score 1 and every hack oracle 0 (Docker; a few minutes a task)
gate: keys
	$(PY) -m rlenvs gate tasks/$(TASK)

gates: keys
	for t in $(TASKS); do $(PY) -m rlenvs gate tasks/$$t || exit 1; done

# the same task through Harbor itself (rlenvs/harbor_env.py records every exec): the honest solution and every oracle
harbor-gate: keys
	mkdir -p $(SCRATCH)/run
	$(PY) -m rlenvs harbor-gate tasks/$(TASK)

# local open-weight episodes, $0
calibrate: keys
	$(PY) -m rlenvs calibrate tasks/$(TASK) --model $(MODEL) --n $(N)

need-cap:
	@test -n "$(MAX_USD)" || { echo "MAX_USD is required: the hard cap on this run's spend, in dollars"; exit 2; }

# PAID: Anthropic-model episodes of every task (TASKS=a b for some), FRONTIER_N each, under the hard cap MAX_USD
# (required); the key is read at run time (ANTHROPIC_API_KEY, else the Keychain). Spend: calibration/spend-ledger.tsv
frontier: need-cap keys
	$(PY) -m rlenvs frontier $(addprefix tasks/,$(TASKS)) --model $(FRONTIER_MODEL) --n $(FRONTIER_N) --max-usd $(MAX_USD)
