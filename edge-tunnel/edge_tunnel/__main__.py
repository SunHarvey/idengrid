from __future__ import annotations

import argparse
import platform

from aiohttp import web

from .app import Settings, create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Authenticated Edge WSS TCP relay")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--config", help="path to protected JSON configuration")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if platform.system() == "Windows":
        if not args.config:
            parser.error("--config is required on Windows")
        settings = Settings.from_file(args.config)
    else:
        if args.config:
            parser.error("--config is supported only on Windows")
        settings = Settings.from_env()
    app = create_app(settings)
    # Intentionally loopback-only: TLS and public exposure belong to Caddy.
    web.run_app(app, host="127.0.0.1", port=args.port, access_log=None)


if __name__ == "__main__":
    main()
