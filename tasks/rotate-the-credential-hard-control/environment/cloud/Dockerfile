FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
COPY cloud.py /cloud/cloud.py
COPY seed.json /srv/cloud/seed.json
HEALTHCHECK --interval=1s --retries=60 CMD python3 -c "import socket; socket.create_connection(('localhost', 8080), 2)"
ENTRYPOINT ["python3", "-I", "/cloud/cloud.py", "serve"]
