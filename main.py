from __future__ import annotations

import argparse

from agent import run_ai_agent
from webapp import run_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Autonomous CTI agent with web dashboard")
    parser.add_argument("--cli", action="store_true", help="Run a single CLI intelligence cycle instead of the web UI.")
    parser.add_argument("--goal", default="", help="Optional custom mission goal for a CLI run.")
    parser.add_argument("--host", default="127.0.0.1", help="Host for the web dashboard.")
    parser.add_argument("--port", type=int, default=8080, help="Port for the web dashboard.")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.cli:
        run_ai_agent(goal=args.goal or None)
    else:
        run_server(host=args.host, port=args.port)
