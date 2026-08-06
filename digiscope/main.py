"""Console/server entry point."""

from __future__ import annotations

import os

import uvicorn

app_import = "digiscope.app:app"


def main() -> None:
    uvicorn.run(
        app_import,
        host=os.getenv("DIGISCOPE_HOST", "0.0.0.0"),
        port=int(os.getenv("DIGISCOPE_PORT", "8000")),
        log_level=os.getenv("DIGISCOPE_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    main()
