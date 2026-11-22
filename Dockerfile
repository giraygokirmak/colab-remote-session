FROM python:3.12.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/nonexistent \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_INPUT=1

RUN groupadd --gid 10001 --system mcp \
    && useradd --uid 10001 --gid mcp --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin mcp

WORKDIR /opt/colab-remote-mcp
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir --no-compile . \
    && mkdir /data \
    && chown mcp:mcp /data

USER 10001:10001
EXPOSE 8000
VOLUME ["/data"]
WORKDIR /data
ENTRYPOINT ["colab-remote-mcp"]
CMD ["--public-url", "http://127.0.0.1:8000", "--keyring-password-file", "/run/keyring.password"]
