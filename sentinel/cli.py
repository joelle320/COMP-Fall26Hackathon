"""Local-only operator commands. No production action adapters are installed."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile


def _write_result(result, destination: str | None):
    content = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if destination:
        output = Path(destination)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content)
        print(f"Saved {output.resolve()}")
    else:
        print(content)


def main():
    parser = argparse.ArgumentParser(description="SENTINEL · agent security, enforced at a local tool gateway")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Start authenticated FastAPI + built React dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--data-dir", default=os.getenv("SENTINEL_DATA_DIR", ".sentinel-data"))
    serve.add_argument("--policy")
    serve.add_argument("--webhook-url")
    serve.add_argument("--webhook-adapter", choices=["siem", "slack", "teams"],
                       default=os.getenv("SENTINEL_WEBHOOK_ADAPTER", "siem"))
    demo = commands.add_parser("demo", help="Run four inert attacks and explicitly simulate local authority approval")
    demo.add_argument("--scenario", choices=["a", "b", "c", "d", "all"], default="all")
    demo.add_argument("--data-dir", help="Persist demo state; otherwise uses an isolated temporary directory")
    demo.add_argument("--output")
    evaluate = commands.add_parser("evaluate", help="Measure the bounded labelled local security fixture corpus")
    evaluate.add_argument("--output", default="work/evaluation.json")
    token = commands.add_parser("token", help="Explicitly display the local authority credential for the dashboard")
    token.add_argument("--data-dir", default=os.getenv("SENTINEL_DATA_DIR", ".sentinel-data"))
    token.add_argument("--role", choices=["admin", "analyst"], default="admin")
    enterprise = commands.add_parser("enterprise-demo", help="Synthetic normal, correlated threat, and reviewed recovery phases")
    enterprise.add_argument("--phase", choices=["normal", "threat", "recovery", "all"], default="all")
    enterprise.add_argument("--data-dir")
    enterprise.add_argument("--output")
    enterprise.add_argument("--approve-sandbox-recovery", action="store_true", help="Explicitly act as local authority to approve, validate and restore synthetic sessions")
    enterprise_eval = commands.add_parser("enterprise-evaluate", help="Measure held-out synthetic AccountWatch and correlation fixtures")
    enterprise_eval.add_argument("--output", default="work/enterprise-evaluation.json")
    args = parser.parse_args()
    if args.command == "serve":
        import uvicorn
        from .api import create_app
        app = create_app(args.data_dir, policy_path=args.policy, webhook_url=args.webhook_url,
                         webhook_adapter=args.webhook_adapter)
        print(f"SENTINEL local sandbox: http://{args.host}:{args.port}")
        print(f"Authority credential: {Path(args.data_dir).resolve() / 'admin.token'} (or SENTINEL_ADMIN_TOKEN)")
        print("Use `python -m sentinel token` to display it explicitly; enter it in the local console.")
        uvicorn.run(app, host=args.host, port=args.port, access_log=False)
    elif args.command == "token":
        from .api import load_authority_token, load_analyst_token
        print(load_analyst_token(Path(args.data_dir).resolve(), create=True) if args.role == "analyst" else load_authority_token(Path(args.data_dir).resolve()))
    elif args.command == "enterprise-demo":
        from .core import Engine
        if args.data_dir:
            result = Engine(Path(args.data_dir)).enterprise.demo(args.phase, complete_recovery=args.approve_sandbox_recovery)
        else:
            with tempfile.TemporaryDirectory(prefix="sentinel-enterprise-") as directory:
                result = Engine(Path(directory)).enterprise.demo(args.phase, complete_recovery=args.approve_sandbox_recovery)
        _write_result(result, args.output)
        if not result.get("passed", False):
            raise SystemExit(1)
    elif args.command == "enterprise-evaluate":
        from .combined_evaluation import evaluate_enterprise_suite
        result = evaluate_enterprise_suite()
        _write_result(result, args.output)
        if result.get("all_required_checks_passed") is False:
            raise SystemExit(1)
    elif args.command == "demo":
        from .core import Engine
        from .demo import run_scenario
        if args.data_dir:
            result = run_scenario(Engine(Path(args.data_dir)), args.scenario, complete_remediation=True)
        else:
            with tempfile.TemporaryDirectory(prefix="sentinel-demo-") as directory:
                result = run_scenario(Engine(Path(directory)), args.scenario, complete_remediation=True)
        _write_result(result, args.output)
        if not result["passed"]:
            raise SystemExit(1)
    elif args.command == "evaluate":
        from .evaluation import evaluate
        result = evaluate()
        _write_result(result, args.output)
        if not result["all_required_checks_passed"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
