"""Run the standalone single-process Streamable HTTP MCP service."""

from __future__ import annotations

import logging

import uvicorn

from colab_remote_mcp.config import parse_args
from colab_remote_mcp.privacy import RedactingFormatter
from colab_remote_mcp.server import create_server


def main() -> None:
    config = parse_args()
    for handler in logging.getLogger().handlers:
        handler.setFormatter(RedactingFormatter("%(levelname)s %(name)s: %(message)s"))
    service = create_server(config)
    server = uvicorn.Server(
        uvicorn.Config(
            service.create_app(),
            host=config.host,
            port=config.port,
            proxy_headers=config.proxy_headers,
            forwarded_allow_ips="127.0.0.1" if config.proxy_headers else None,
            server_header=False,
            access_log=False,
        )
    )
    server.run()


if __name__ == "__main__":
    main()
