#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template_string

from scripts.analyze_d8_log import summarize_log


def load_status(status_path: Path) -> dict[str, Any]:
    if not status_path.exists():
        return {}
    try:
        return json.loads(status_path.read_text())
    except json.JSONDecodeError:
        return {}


def load_crash_summaries(out_dir: Path) -> list[dict[str, int]]:
    summaries: list[dict[str, int]] = []
    for log_file in sorted(out_dir.glob("*.log")):
        summaries.append(summarize_log(log_file))
    return summaries


def summarize_crash_features(summaries: list[dict[str, int]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for summary in summaries:
        for key, value in summary.items():
            totals[key] = totals.get(key, 0) + value
    return totals


def suggest_grammar_from_crashes(totals: dict[str, int]) -> dict[str, str]:
    suggestions: dict[str, str] = {}
    if totals.get("bounds_checks", 0) > 20:
        suggestions["length"] = "Emphasize length and holey mutations."
    if totals.get("type_checks", 0) > 20:
        suggestions["maps"] = "Increase map/prototype flipping attacks."
    if totals.get("overflow_checks", 0) > 5:
        suggestions["arith"] = "Increase integer/float arithmetic attacks."
    if totals.get("deopt_points", 0) > 10:
        suggestions["proxy"] = "Increase proxy-based length and side-effect accesses."
    if not suggestions:
        suggestions["baseline"] = "No dominant pattern yet; keep broad attack coverage."
    return suggestions


def create_app(out_dir: Path, status_path: Path) -> Flask:
    app = Flask(__name__)

    template = """
    <!doctype html>
    <html>
      <head>
        <title>V8 Fuzzing Dashboard</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 2rem; }
          .panel { margin-bottom: 1.5rem; padding: 1rem; border: 1px solid #ccc; }
          .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; }
          pre { background: #f6f8fa; padding: 0.75rem; }
        </style>
      </head>
      <body>
        <h1>V8 Fuzzing Dashboard</h1>
        <div class="panel">
          <h2>Live Status</h2>
          <pre>{{ status | tojson(indent=2) }}</pre>
        </div>
        <div class="panel">
          <h2>Crash Analysis</h2>
          <div class="grid">
            <div>
              <h3>Totals</h3>
              <pre>{{ crash_totals | tojson(indent=2) }}</pre>
            </div>
            <div>
              <h3>Grammar Suggestions</h3>
              <pre>{{ grammar_suggestions | tojson(indent=2) }}</pre>
            </div>
          </div>
        </div>
        <div class="panel">
          <h2>Recent Crash Logs</h2>
          <ul>
            {% for log in crash_logs %}
              <li>{{ log }}</li>
            {% else %}
              <li>No crash logs yet.</li>
            {% endfor %}
          </ul>
        </div>
      </body>
    </html>
    """

    @app.route("/")
    def index() -> str:
        status = load_status(status_path)
        summaries = load_crash_summaries(out_dir)
        crash_totals = summarize_crash_features(summaries)
        grammar_suggestions = suggest_grammar_from_crashes(crash_totals)
        crash_logs = [p.name for p in sorted(out_dir.glob("*.log"))][-20:]
        return render_template_string(
            template,
            status=status,
            crash_totals=crash_totals,
            grammar_suggestions=grammar_suggestions,
            crash_logs=crash_logs,
        )

    @app.route("/status")
    def status_api() -> Any:
        return jsonify(load_status(status_path))

    @app.route("/analysis")
    def analysis_api() -> Any:
        summaries = load_crash_summaries(out_dir)
        crash_totals = summarize_crash_features(summaries)
        return jsonify(
            {
                "totals": crash_totals,
                "grammar_suggestions": suggest_grammar_from_crashes(crash_totals),
            }
        )

    return app


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a dashboard for V8 fuzzing")
    parser.add_argument("--out", default="crashes", help="Output directory with crash logs")
    parser.add_argument(
        "--status-file",
        default="crashes/status.json",
        help="Status file written by the fuzzer",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    out_dir = Path(args.out)
    status_path = Path(args.status_file)
    app = create_app(out_dir, status_path)
    app.run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
