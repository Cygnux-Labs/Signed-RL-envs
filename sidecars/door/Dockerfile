FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
# the observer records each attempt through Tracekit's client, pinned as the signer is
RUN pip install --no-cache-dir tracekit-ai==1.5.3
COPY door.py scan.py /door/
# the file hosts the task plays (DOOR_SERVE): serve/<host>/..., built in, never mounted
COPY serve /door/serve
ENTRYPOINT ["python", "-I", "/door/door.py"]
