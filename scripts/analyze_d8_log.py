#!/usr/bin/env python3
"""
D8 Turbofan/Maglev Output Analyzer (text-only)
Extracts useful information from D8 compiler output and summarizes findings
for bug hunting and vulnerability research.
"""

import argparse
import re
from collections import Counter
from pathlib import Path

SECTION_START = "----- After register allocation -----"


def clean_ansi(text: str) -> str:
    ansi_escape = re.compile(
        r"\x1b\[[0-9;]*[mGKHf]|\x1b\[\?[0-9;]*[lh]|[\x00-\x1f\x7f-\x9f]"
    )
    return ansi_escape.sub("", text)


def parse_blocks(log_text: str) -> dict[str, str]:
    blocks: dict[str, str] = {}
    current_block = None
    content: list[str] = []
    start_parsing = False

    for line in log_text.splitlines():
        if SECTION_START in line:
            start_parsing = True
            continue
        if not start_parsing:
            continue

        block_match = re.search(r"Block\s+(b\d+)", line)
        if block_match:
            if current_block:
                blocks[current_block] = "\n".join(content)
            current_block = block_match.group(1)
            content = []
            continue

        if current_block:
            cleaned = clean_ansi(line.rstrip())
            if cleaned:
                content.append(cleaned)

    if current_block:
        blocks[current_block] = "\n".join(content)

    return blocks


def extract_metadata(blocks: dict[str, str]) -> dict[str, Counter]:
    metadata: dict[str, Counter] = {
        "deopt_points": Counter(),
        "bounds_checks": Counter(),
        "type_checks": Counter(),
        "overflow_checks": Counter(),
        "loop_edges": Counter(),
        "function_calls": Counter(),
        "memory_operations": Counter(),
    }

    for block_id, code in blocks.items():
        if "Deopt" in code or "eager @" in code or "lazy @" in code:
            for deopt_type, offset in re.findall(r"(eager|lazy) @(\d+)", code):
                metadata["deopt_points"][f"{block_id}:{deopt_type}@{offset}"] += 1

        if "CheckInt32Condition" in code and "OutOfBounds" in code:
            for check in re.findall(r"CheckInt32Condition\((.*?)\, OutOfBounds\)", code):
                metadata["bounds_checks"][f"{block_id}:{check}"] += 1

        if "CheckMaps" in code:
            for check in re.findall(r"CheckMaps\((.*?)\)", code):
                metadata["type_checks"][f"{block_id}:{check}"] += 1

        if "WithOverflow" in code:
            for check in re.findall(r"(\w+WithOverflow)", code):
                metadata["overflow_checks"][f"{block_id}:{check}"] += 1

        if "JumpLoop" in code:
            for target in re.findall(r"JumpLoop\s+(b\d+)", code):
                metadata["loop_edges"][f"{block_id}->{target}"] += 1

        if "Call" in code:
            for call in re.findall(r"(Call\w+)", code):
                metadata["function_calls"][call] += 1

        for op in re.findall(r"(Load\w+|Store\w+)", code):
            metadata["memory_operations"][op] += 1

    return metadata


def summarize_log(log_path: Path) -> dict[str, int]:
    log_text = log_path.read_text(errors="ignore")
    blocks = parse_blocks(log_text)
    metadata = extract_metadata(blocks)

    return {
        "blocks": len(blocks),
        "deopt_points": sum(metadata["deopt_points"].values()),
        "bounds_checks": sum(metadata["bounds_checks"].values()),
        "type_checks": sum(metadata["type_checks"].values()),
        "overflow_checks": sum(metadata["overflow_checks"].values()),
        "loop_edges": sum(metadata["loop_edges"].values()),
        "function_calls": sum(metadata["function_calls"].values()),
        "memory_operations": sum(metadata["memory_operations"].values()),
    }


def render_report(log_path: Path) -> str:
    summary = summarize_log(log_path)
    lines = ["=" * 72, f"D8 ANALYZER REPORT: {log_path}", "=" * 72]
    for key, value in summary.items():
        lines.append(f"{key}: {value}")
    lines.append("=" * 72)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze D8 output logs")
    parser.add_argument("log_file", help="Path to D8 output log file")
    parser.add_argument("--report", help="Output file for text report", default=None)
    args = parser.parse_args()

    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"Log file not found: {log_path}")
        return 2

    report = render_report(log_path)
    print(report)

    if args.report:
        Path(args.report).write_text(report)
        print(f"Report saved to {args.report}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
