"""``python -m whitelister``: load the configuration and serve the app."""

from __future__ import annotations

import logging
import sys

import uvicorn

from .config import ConfigError, load_settings


def main() -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("whitelister.audit").setLevel(logging.INFO)  # the audit trail does not follow LOG_LEVEL
    from .app import create_app

    app = create_app(settings)
    uvicorn.run(
        app,
        host=settings.listen_host,
        port=settings.listen_port,
        log_level=settings.log_level,
        proxy_headers=False,  # the app resolves the client address itself (TRUSTED_PROXIES)
        forwarded_allow_ips=[],
        server_header=False,
        date_header=False,
        access_log=False,
        limit_concurrency=100,
        timeout_keep_alive=5,
        h11_max_incomplete_event_size=16 * 1024,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
