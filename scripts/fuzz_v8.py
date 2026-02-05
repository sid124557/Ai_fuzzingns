#!/usr/bin/env python3
import argparse
import random
import re
import subprocess
import time
from pathlib import Path

from scripts.analyze_d8_log import summarize_log

MAGLEV_PATTERNS = {
    "checkmaps": re.compile(r"CheckMaps"),
    "checkbounds": re.compile(r"CheckBounds"),
    "deopts": re.compile(r"deopt", re.IGNORECASE),
    "inlining": re.compile(r"Inlined"),
    "elements_transitions": re.compile(r"elements transition", re.IGNORECASE),
}

BASE_TEMPLATE = r"""
// ============================================================================
// V8 SEGFAULT FUZZ TEMPLATE
// ============================================================================

const ATTACKER_COUNT = {attacker_count};

function makeAttackers(seed) {{
  let attackers = new Array(ATTACKER_COUNT);
  let x = seed | 0;
  for (let i = 0; i < attackers.length; i++) {{
    x = (x * 1103515245 + 12345) | 0;
    let mode = x & 7;
    attackers[i] = function attacker(slot, target) {{
      switch (mode) {{
        case 0:
          target.length = (slot & 3) + 1;
          return target[slot];
        case 1: {{
          let tmp = new Array(8);
          tmp[0] = target;
          tmp[1] = tmp;
          return tmp[(slot ^ 1) & 7];
        }}
        case 2: {{
          let t = new Uint8Array(64);
          t[slot & 63] = slot & 255;
          return t[slot & 63];
        }}
        case 3: {{
          let map = new Map();
          map.set("k", target);
          map.set(slot, slot + 0.1);
          return map.get("k");
        }}
        case 4:
          delete target[slot & 3];
          return target[slot & 3];
        case 5:
          target[slot & 1] = {ptr: slot, tag: "obj"};
          return target[slot & 1];
        case 6:
          return Math.imul(slot, 1337) ^ (slot >>> 1);
        default:
          return (slot + 0.5) / (slot + 1);
      }}
    }};
  }}
  return attackers;
}}

function vulnerableRead(arr) {
  let len = arr.length;
  return arr[len + {oob_offset}];
}

// Warmup
let stable = [];
for (let i = 0; i < {warmup}; i++) stable[i] = i * 2.5;

for (let i = 0; i < {pre_opt}; i++) {
  vulnerableRead(stable);
}

%PrepareFunctionForOptimization(vulnerableRead);
for (let i = 0; i < {opt_calls}; i++) vulnerableRead(stable);
%OptimizeFunctionOnNextCall(vulnerableRead);
vulnerableRead(stable);

let victim = [];
for (let i = 0; i < 5; i++) {
  victim[i] = i * 1.1;
}
delete victim[2]; // HOLEY_DOUBLE_ELEMENTS

let callCount = 0;
let attackers = makeAttackers({seed});

let proxy = new Proxy(victim, {
  get(target, prop, receiver) {
    if (prop === 'length') {
      callCount++;

      // === PHASE 1: FREE THE OLD BACKING STORE ===
      gc(); gc(); gc();

      for (let i = 0; i < {reallocs}; i++) {
        target.push(100 + i);
      }

      // === PHASE 2: CHANGE ELEMENT KIND ===
      target[0] = {ptr: 0xDEADBEEF};
      target[1] = {ptr: 0xCAFEBABE};
      target[2] = {ptr: 0x41414141};

      // === PHASE 3: SPRAY HEAP ===
      let spray = [];
      for (let i = 0; i < {spray_count}; i++) {
        spray.push({
          marker: 0xDEADC0DE,
          index: i,
          padding: new Array({spray_pad}).fill(0x42424242)
        });

        if (i % {gc_interval} === 0) {
          gc();
        }
      }

      // === PHASE 4: DESTABILIZATION ===
      target.length = {shrink_len};
      target.push(999.999);

      delete target[0];
      delete target[1];

      // === PHASE 5: FINAL GC ===
      gc(); gc(); gc();

      if (callCount % {huge_every} === 0) {
        let huge = new Array({huge_size});
        for (let i = 0; i < {huge_size}; i++) huge[i] = i;
        huge = null;
        gc();
      }

      return {fake_length};
    }

    return Reflect.get(target, prop, receiver);
  }
});

let successfulReads = 0;
let exceptions = 0;

for (let i = 0; i < {iterations}; i++) {
  try {
    let val = vulnerableRead(proxy);
    let attacker = attackers[i % attackers.length];
    let havoc = attacker(i, victim);

    if (val !== undefined && val !== null && typeof val === 'object') {
      try {
        Object.keys(val);
        val.toString();
        JSON.stringify(val);
      } catch (innerE) {
        // swallow
      }
    }

    if (havoc && typeof havoc === 'object') {
      try {
        if (Array.isArray(havoc)) havoc.length = 1;
        if (havoc && havoc.buffer) new Uint8Array(havoc.buffer);
      } catch (innerE) {
        // swallow
      }
    }

    successfulReads++;

  } catch (e) {
    exceptions++;
  }

  if (i % {outer_gc_interval} === 0) {
    gc(); gc();
  }

  for (let j = 0; j < {spin}; j++) {
    Math.random();
  }
}

print('successfulReads=' + successfulReads + ' exceptions=' + exceptions);
"""

DEFAULT_FLAGS = [
    "--allow-natives-syntax",
    "--expose-gc",
    "--print-opt-code",
    "--trace-turbo",
    "--trace-deopt",
    "--maglev",
    "--print-maglev-graph",
    "--verify-heap",
    "--no-concurrent-gc",
    "--no-lazy-feedback-allocation",
    "--max-old-space-size=100",
]

CRASH_STRINGS = [
    "Segmentation fault",
    "SEGV",
    "Access violation",
    "AddressSanitizer",
    "SIGSEGV",
    "Fatal error",
]


def random_params(rng: random.Random) -> dict:
    return {
        "oob_offset": rng.randint(32, 300),
        "warmup": rng.randint(1000, 8000),
        "pre_opt": rng.randint(1000, 20000),
        "opt_calls": rng.randint(50, 600),
        "reallocs": rng.randint(10, 120),
        "spray_count": rng.randint(2000, 25000),
        "spray_pad": rng.randint(10, 80),
        "gc_interval": rng.randint(200, 2000),
        "shrink_len": rng.randint(1, 4),
        "huge_every": rng.randint(3, 9),
        "huge_size": rng.randint(20000, 150000),
        "fake_length": rng.randint(50, 400),
        "iterations": rng.randint(50, 400),
        "outer_gc_interval": rng.randint(1, 6),
        "spin": rng.randint(200, 2000),
        "attacker_count": rng.randint(500, 10000),
        "seed": rng.randint(1, 1_000_000),
    }


def scale_range(rng: random.Random, low: int, high: int, scale: float) -> int:
    scaled_low = max(1, int(low * scale))
    scaled_high = max(scaled_low + 1, int(high * scale))
    return rng.randint(scaled_low, scaled_high)


def apply_tuning(params: dict, rng: random.Random, tuning: dict[str, float]) -> dict:
    tuned = dict(params)
    tuned["spray_count"] = scale_range(
        rng, 2000, 25000, tuning.get("spray_scale", 1.0)
    )
    tuned["attacker_count"] = scale_range(
        rng, 500, 10000, tuning.get("attacker_scale", 1.0)
    )
    tuned["iterations"] = scale_range(
        rng, 50, 400, tuning.get("iterations_scale", 1.0)
    )
    tuned["spin"] = scale_range(rng, 200, 2000, tuning.get("spin_scale", 1.0))
    tuned["oob_offset"] = scale_range(
        rng, 32, 300, tuning.get("oob_scale", 1.0)
    )
    return tuned


def render_case(
    case_id: str,
    rng: random.Random,
    attacker_count: int | None,
    tuning: dict[str, float] | None,
) -> str:
    params = random_params(rng)
    if attacker_count is not None:
        params["attacker_count"] = attacker_count
    if tuning:
        params = apply_tuning(params, rng, tuning)
    return BASE_TEMPLATE.format(**params), params


def parse_maglev_output(output: str) -> dict[str, int]:
    stats: dict[str, int] = {}
    for key, pattern in MAGLEV_PATTERNS.items():
        stats[key] = len(pattern.findall(output))
    return stats


def score_maglev(stats: dict[str, int]) -> int:
    score = 0
    score += max(0, 12 - stats["checkmaps"])
    score += max(0, 12 - stats["checkbounds"])
    score += stats["deopts"] * 3
    score += stats["inlining"] * 4
    score += stats["elements_transitions"] * 2
    return score


def update_tuning(tuning: dict[str, float], stats: dict[str, int]) -> dict[str, float]:
    next_tuning = dict(tuning)
    if stats["deopts"] < 2:
        next_tuning["spray_scale"] = min(2.0, next_tuning["spray_scale"] + 0.1)
        next_tuning["attacker_scale"] = min(2.0, next_tuning["attacker_scale"] + 0.1)
    if stats["checkmaps"] > 8:
        next_tuning["oob_scale"] = min(1.8, next_tuning["oob_scale"] + 0.1)
    if stats["inlining"] == 0:
        next_tuning["iterations_scale"] = min(1.8, next_tuning["iterations_scale"] + 0.1)
        next_tuning["spin_scale"] = min(1.8, next_tuning["spin_scale"] + 0.1)
    return next_tuning


def run_case(d8_path: Path, js_path: Path, flags: list[str], timeout_s: int) -> tuple[int, str]:
    cmd = [str(d8_path), *flags, str(js_path)]
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_s,
    )
    return proc.returncode, proc.stdout


def is_crash(returncode: int, output: str) -> bool:
    if returncode != 0:
        return True
    output_lower = output.lower()
    return any(s.lower() in output_lower for s in CRASH_STRINGS)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fuzz V8 d8 with aggressive OOB template")
    parser.add_argument("--d8", required=True, help="Path to d8 binary")
    parser.add_argument("--out", default="crashes", help="Output directory for crashers")
    parser.add_argument("--iterations", type=int, default=50, help="Number of fuzz iterations")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout per run (seconds)")
    parser.add_argument("--seed", type=int, default=None, help="Random seed")
    parser.add_argument(
        "--attacker-count",
        type=int,
        default=None,
        help="Number of attacker functions to generate (default: random 500-10000)",
    )
    parser.add_argument(
        "--maglev-guided",
        action="store_true",
        help="Use Maglev output stats to steer generation and keep interesting cases",
    )
    parser.add_argument(
        "--maglev-threshold",
        type=int,
        default=18,
        help="Minimum Maglev score to keep non-crashing cases when guided",
    )
    parser.add_argument(
        "--keep-interesting",
        action="store_true",
        help="Keep non-crashing cases that meet the Maglev score threshold",
    )
    parser.add_argument("--flags", nargs="*", default=DEFAULT_FLAGS, help="Extra d8 flags")
    parser.add_argument(
        "--analyze-crashes",
        action="store_true",
        help="Analyze crash logs for patterns and print a summary",
    )

    args = parser.parse_args()

    d8_path = Path(args.d8)
    if not d8_path.exists():
        print(f"d8 not found: {d8_path}")
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(args.seed)
    tuning = {
        "spray_scale": 1.0,
        "attacker_scale": 1.0,
        "iterations_scale": 1.0,
        "spin_scale": 1.0,
        "oob_scale": 1.0,
    }

    print(f"[+] Running {args.iterations} fuzz iterations")

    crashes = 0
    for i in range(args.iterations):
        case_id = f"case_{int(time.time())}_{i}_{rng.randint(1000,9999)}"
        js_text, params = render_case(
            case_id,
            rng,
            args.attacker_count,
            tuning if args.maglev_guided else None,
        )

        js_path = out_dir / f"{case_id}.js"
        meta_path = out_dir / f"{case_id}.meta"
        log_path = out_dir / f"{case_id}.log"

        js_path.write_text(js_text)
        meta_path.write_text("\n".join([f"{k}={v}" for k, v in params.items()]))

        try:
            returncode, output = run_case(d8_path, js_path, args.flags, args.timeout)
        except subprocess.TimeoutExpired:
            returncode = 124
            output = "TIMEOUT"

        log_path.write_text(output)

        maglev_stats = {}
        maglev_score = 0
        if args.maglev_guided:
            maglev_stats = parse_maglev_output(output)
            maglev_score = score_maglev(maglev_stats)
            tuning = update_tuning(tuning, maglev_stats)
            print(f"[MAGLEV] {case_id} score={maglev_score} stats={maglev_stats}")
            meta_path.write_text(
                meta_path.read_text()
                + "\n"
                + "\n".join([f"maglev_{k}={v}" for k, v in maglev_stats.items()])
                + f"\nmaglev_score={maglev_score}\n"
            )

        if is_crash(returncode, output):
            crashes += 1
            print(f"[CRASH] {case_id} returncode={returncode}")
        else:
            keep_interesting = (
                args.maglev_guided
                and args.keep_interesting
                and maglev_score >= args.maglev_threshold
            )
            if keep_interesting:
                print(
                    f"[INTERESTING] {case_id} maglev_score={maglev_score} stats={maglev_stats}"
                )
            else:
                # Clean up non-crashes to keep output concise
                js_path.unlink(missing_ok=True)
                meta_path.unlink(missing_ok=True)
                log_path.unlink(missing_ok=True)

    if args.analyze_crashes and crashes:
        print("[+] Analyzing crash logs...")
        summaries = []
        for log_file in sorted(out_dir.glob("*.log")):
            summaries.append(summarize_log(log_file))

        if summaries:
            print("[+] Crash log pattern summary")
            for key in sorted(summaries[0].keys()):
                total = sum(summary.get(key, 0) for summary in summaries)
                print(f"  {key}: {total}")

    print(f"[+] Finished. Crashes found: {crashes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
