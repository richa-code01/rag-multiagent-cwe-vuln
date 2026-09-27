"""Start the operator console on localhost only."""

from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="Local operator console for cwe-vuln.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print("refusing to bind outside localhost; this console has no authentication")
        return 1
    uvicorn.run("cwe_vuln.api.app:app", host=args.host, port=args.port, log_level="info")
    return 0
