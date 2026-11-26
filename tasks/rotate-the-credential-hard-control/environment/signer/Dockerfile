FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
# the open instrument, from PyPI, pinned
RUN pip install --no-cache-dir tracekit-ai==1.5.3
COPY entrypoint.py policy.yaml /etc/rlenv/
# the per-build log key (make keys); only this image has it, never the agent's
COPY keys /etc/rlenv/keys
ENTRYPOINT ["python", "-I", "/etc/rlenv/entrypoint.py"]
