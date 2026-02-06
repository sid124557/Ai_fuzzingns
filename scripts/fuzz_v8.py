#!/usr/bin/env python3
import argparse
import random
import re
import subprocess
import time
from collections import Counter, deque
from pathlib import Path
from collections import Counter, deque

from scripts.analyze_d8_log import summarize_log
from scripts.fuzzing.plans import (
    build_attack_plan,
    build_mutation_plan,
    init_attack_weights,
    init_mutation_weights,
    update_attack_weights,
    update_mutation_weights,
)
from scripts.fuzzing.signals import (
    compute_deviation_score,
    detect_coverage,
    detect_patterns,
    parse_maglev_output,
)

MAGLEV_PATTERNS = {
    "checkmaps": re.compile(r"CheckMaps"),
    "checkbounds": re.compile(r"CheckBounds"),
    "deopts": re.compile(r"deopt", re.IGNORECASE),
    "inlining": re.compile(r"Inlined"),
    "elements_transitions": re.compile(r"elements transition", re.IGNORECASE),
}

PATTERN_REGEXES = {
    "checkmaps": re.compile(r"CheckMaps"),
    "checkbounds": re.compile(r"CheckBounds"),
    "deopt_lazy": re.compile(r"\blazy\b", re.IGNORECASE),
    "deopt_eager": re.compile(r"\beager\b", re.IGNORECASE),
    "inline": re.compile(r"Inlined"),
    "elements_transition": re.compile(r"elements transition", re.IGNORECASE),
    "allocation": re.compile(r"Allocate|NewSpace", re.IGNORECASE),
    "bounds": re.compile(r"OutOfBounds|CheckBounds", re.IGNORECASE),
}

COVERAGE_REGEXES = {
    "blocks": re.compile(r"\bBlock\s+(b\d+)\b"),
    "ops": re.compile(r"\b(CheckMaps|CheckBounds|Load\w+|Store\w+|Call\w+)\b"),
}

BASE_TEMPLATE = r"""
// ============================================================================
// V8 SEGFAULT FUZZ TEMPLATE
// ============================================================================

const ATTACKER_COUNT = {attacker_count};
const MUTATION_COUNT = {mutation_count};

const ATTACKS = [
{attacker_plan}
];

const MUTATIONS = [
{mutation_plan}
];

function makeAttackers(seed) {{
  let attackers = new Array(ATTACKER_COUNT);
  let x = seed | 0;
  for (let i = 0; i < attackers.length; i++) {{
    x = (x * 1103515245 + 12345) | 0;
    let mode = (x >>> 0) % ATTACKS.length;
    attackers[i] = ATTACKS[mode];
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

function applyMutations(target, i) {
  for (let j = 0; j < MUTATIONS.length; j++) {
    try {
      MUTATIONS[j](target, i);
    } catch (e) {
      // swallow
    }
  }
}

for (let i = 0; i < {iterations}; i++) {
  try {
    let val = vulnerableRead(proxy);
    let attacker = attackers[i % attackers.length];
    let havoc = attacker(i, victim);
    applyMutations(victim, i);

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

ATTACK_LIBRARY = [
    {
        "name": "length_flip",
        "tag": "length",
        "code": """
target.length = (slot & 3) + 1;
return target[slot];
""",
    },
    {
        "name": "self_ref_array",
        "tag": "maps",
        "code": """
let tmp = new Array(8);
tmp[0] = target;
tmp[1] = tmp;
return tmp[(slot ^ 1) & 7];
""",
    },
    {
        "name": "typed_store",
        "tag": "typed",
        "code": """
let t = new Uint8Array(64);
t[slot & 63] = slot & 255;
return t[slot & 63];
""",
    },
    {
        "name": "map_lookup",
        "tag": "maps",
        "code": """
let map = new Map();
map.set("k", target);
map.set(slot, slot + 0.1);
return map.get("k");
""",
    },
    {
        "name": "holey_delete",
        "tag": "holey",
        "code": """
delete target[slot & 3];
return target[slot & 3];
""",
    },
    {
        "name": "object_write",
        "tag": "maps",
        "code": """
target[slot & 1] = {ptr: slot, tag: "obj"};
return target[slot & 1];
""",
    },
    {
        "name": "int_math",
        "tag": "arith",
        "code": """
return Math.imul(slot, 1337) ^ (slot >>> 1);
""",
    },
    {
        "name": "float_math",
        "tag": "arith",
        "code": """
return (slot + 0.5) / (slot + 1);
""",
    },
    {
        "name": "prototype_flip",
        "tag": "maps",
        "code": """
Object.setPrototypeOf(target, (slot & 1) ? [] : {x: 1});
return target.length;
""",
    },
    {
        "name": "length_proxy",
        "tag": "proxy",
        "code": """
let p = new Proxy(target, {
  get(t, prop, receiver) {
    if (prop === "length") {
      gc();
    }
    return Reflect.get(t, prop, receiver);
  }
});
return p.length;
""",
    },
    {
        "name": "arraybuffer_view",
        "tag": "typed",
        "code": """
let buf = new ArrayBuffer(64);
let view = new Uint32Array(buf);
view[slot & 15] = slot >>> 0;
return view[slot & 15];
""",
    },
    {
        "name": "dense_fill",
        "tag": "length",
        "code": """
for (let i = 0; i < 6; i++) {
  target[i] = slot + i + 0.25;
}
return target[slot & 3];
""",
    },
]

ATTACK_TAGS = {attack["tag"] for attack in ATTACK_LIBRARY}

MUTATION_LIBRARY = [
    {
        "name": "flip_to_object",
        "tag": "maps",
        "code": """
target[0] = {flip: i};
target[1] = {flip: i + 1};
target[2] = {flip: i + 2};
""",
    },
    {
        "name": "make_holey",
        "tag": "holey",
        "code": """
delete target[i & 3];
""",
    },
    {
        "name": "shrink_length",
        "tag": "length",
        "code": """
target.length = (i & 3) + 1;
""",
    },
    {
        "name": "extend_length",
        "tag": "length",
        "code": """
target.length = 20 + (i & 7);
""",
    },
    {
        "name": "typedarray_view",
        "tag": "typed",
        "code": """
let ta = new Uint8Array(32);
ta[i & 31] = i & 255;
target[i & 3] = ta[i & 31];
""",
    },
    {
        "name": "prototype_swap",
        "tag": "maps",
        "code": """
Object.setPrototypeOf(target, (i & 1) ? [] : {x: 1});
""",
    },
    {
        "name": "define_property",
        "tag": "maps",
        "code": """
Object.defineProperty(target, "x" + (i & 3), {value: i, configurable: true});
""",
    },
    {
        "name": "seal_once",
        "tag": "maps",
        "code": """
if ((i & 7) === 0) {
  Object.seal(target);
}
""",
    },
    {
        "name": "proxy_length_peek",
        "tag": "proxy",
        "code": """
let p = new Proxy(target, {
  get(t, prop, receiver) {
    if (prop === "length") {
      gc();
    }
    return Reflect.get(t, prop, receiver);
  }
});
p.length;
""",
    },
    {
        "name": "gc_pressure",
        "tag": "gc",
        "code": """
if ((i & 15) === 0) {
  let junk = new Array(256).fill(i);
  junk[0] = target;
}
""",
    },
]

MUTATION_TAGS = {mutation["tag"] for mutation in MUTATION_LIBRARY}


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
        "attacker_count": rng.randint(1000, 10000),
        "seed": rng.randint(1, 1_000_000),
        "attack_plan_size": rng.randint(5000, 8000),
        "mutation_count": rng.randint(6, 12),
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
        rng, 1000, 10000, tuning.get("attacker_scale", 1.0)
    )
    tuned["attack_plan_size"] = scale_range(
        rng, 5000, 8000, tuning.get("attack_plan_scale", 1.0)
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
) -> tuple[str, dict, list[str], list[str]]:
    params = random_params(rng)
    if attacker_count is not None:
        params["attacker_count"] = attacker_count
    if tuning:
        params = apply_tuning(params, rng, tuning)
    attack_weights = (
        tuning["attack_weights"]
        if tuning and "attack_weights" in tuning
        else init_attack_weights()
    )
    attack_plan, attack_names = build_attack_plan(
        rng, params["attack_plan_size"], attack_weights
    )
    params["attacker_plan"] = attack_plan
    mutation_weights = (
        tuning["mutation_weights"]
        if tuning and "mutation_weights" in tuning
        else init_mutation_weights()
    )
    mutation_plan, mutation_names = build_mutation_plan(
        rng, params["mutation_count"], mutation_weights
    )
    params["mutation_plan"] = mutation_plan
    return BASE_TEMPLATE.format(**params), params, attack_names, mutation_names


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
    next_tuning["attack_weights"] = update_attack_weights(
        next_tuning.get("attack_weights", init_attack_weights()), stats
    )
    next_tuning["mutation_weights"] = update_mutation_weights(
        next_tuning.get("mutation_weights", init_mutation_weights()), stats
    )
    return next_tuning


def update_tuning_from_history(
    tuning: dict[str, float],
    history: deque[dict[str, int]],
    pattern_history: deque[Counter],
    coverage_history: deque[dict[str, int]],
) -> dict[str, float]:
    if not history:
        return tuning
    avg = Counter()
    for entry in history:
        avg.update(entry)
    for key in list(avg.keys()):
        avg[key] = avg[key] / len(history)

    pattern_avg = Counter()
    for entry in pattern_history:
        pattern_avg.update(entry)
    for key in list(pattern_avg.keys()):
        pattern_avg[key] = pattern_avg[key] / len(pattern_history)

    coverage_avg = Counter()
    for entry in coverage_history:
        coverage_avg.update(entry)
    for key in list(coverage_avg.keys()):
        coverage_avg[key] = coverage_avg[key] / len(coverage_history)

    next_tuning = dict(tuning)
    if avg["checkmaps"] > 10:
        next_tuning["attack_weights"]["maps"] = min(
            2.0, next_tuning["attack_weights"]["maps"] + 0.1
        )
    if avg["checkbounds"] > 10 or pattern_avg["bounds"] > 4:
        next_tuning["attack_weights"]["length"] = min(
            2.0, next_tuning["attack_weights"]["length"] + 0.1
        )
        next_tuning["mutation_weights"]["length"] = min(
            2.0, next_tuning["mutation_weights"]["length"] + 0.1
        )
    if avg["deopts"] < 2 and pattern_avg["deopt_lazy"] < 1:
        next_tuning["attack_weights"]["proxy"] = min(
            2.0, next_tuning["attack_weights"]["proxy"] + 0.1
        )
        next_tuning["mutation_weights"]["proxy"] = min(
            2.0, next_tuning["mutation_weights"]["proxy"] + 0.1
        )
    if avg["elements_transitions"] == 0 and pattern_avg["elements_transition"] == 0:
        next_tuning["attack_weights"]["typed"] = min(
            2.0, next_tuning["attack_weights"]["typed"] + 0.1
        )
        next_tuning["mutation_weights"]["typed"] = min(
            2.0, next_tuning["mutation_weights"]["typed"] + 0.1
        )
    if pattern_avg["allocation"] > 5:
        next_tuning["spray_scale"] = min(2.0, next_tuning["spray_scale"] + 0.1)
    if coverage_avg["blocks"] < 10:
        next_tuning["attack_plan_scale"] = min(
            1.6, next_tuning.get("attack_plan_scale", 1.0) + 0.1
        )
    if coverage_avg["ops"] < 10:
        next_tuning["iterations_scale"] = min(
            1.8, next_tuning.get("iterations_scale", 1.0) + 0.1
        )
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
        help="Number of attacker functions to generate (default: random 1000-10000)",
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
    parser.add_argument(
        "--baseline-runs",
        type=int,
        default=5,
        help="Number of initial runs to learn baseline patterns before targeting deviations",
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
        "attack_plan_scale": 1.0,
        "iterations_scale": 1.0,
        "spin_scale": 1.0,
        "oob_scale": 1.0,
        "attack_weights": init_attack_weights(),
        "mutation_weights": init_mutation_weights(),
    }
    maglev_history: deque[dict[str, int]] = deque(maxlen=6)
    pattern_history: deque[Counter] = deque(maxlen=6)
    coverage_history: deque[dict[str, int]] = deque(maxlen=6)
    baseline_patterns: list[Counter] = []
    baseline_coverages: list[dict[str, int]] = []
    baseline_stats: list[dict[str, int]] = []

    print(f"[+] Running {args.iterations} fuzz iterations")

    crashes = 0
    for i in range(args.iterations):
        case_id = f"case_{int(time.time())}_{i}_{rng.randint(1000,9999)}"
        js_text, params, attack_names, mutation_names = render_case(
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
        meta_path.write_text(
            meta_path.read_text()
            + f"\nattacks={','.join(attack_names)}\n"
            + f"mutations={','.join(mutation_names)}\n"
        )

        try:
            returncode, output = run_case(d8_path, js_path, args.flags, args.timeout)
        except subprocess.TimeoutExpired:
            returncode = 124
            output = "TIMEOUT"

        log_path.write_text(output)

        if i == 0 or (i + 1) % max(1, args.iterations // 10) == 0:
            print(
                f"[PROGRESS] {i + 1}/{args.iterations} "
                f"latest=case:{case_id} returncode={returncode}"
            )

        maglev_stats = {}
        maglev_score = 0
        pattern_stats = Counter()
        coverage_stats = {}
        deviation_score = 0.0
        if args.maglev_guided:
            maglev_stats = parse_maglev_output(output)
            maglev_score = score_maglev(maglev_stats)
            tuning = update_tuning(tuning, maglev_stats)
            pattern_stats = detect_patterns(output)
            coverage_stats = detect_coverage(output)
            if len(baseline_patterns) < args.baseline_runs:
                baseline_patterns.append(pattern_stats)
                baseline_coverages.append(coverage_stats)
                baseline_stats.append(maglev_stats)
            else:
                baseline_pattern_avg = Counter()
                for entry in baseline_patterns:
                    baseline_pattern_avg.update(entry)
                for key in list(baseline_pattern_avg.keys()):
                    baseline_pattern_avg[key] = (
                        baseline_pattern_avg[key] / len(baseline_patterns)
                    )
                baseline_coverage_avg = Counter()
                for entry in baseline_coverages:
                    baseline_coverage_avg.update(entry)
                for key in list(baseline_coverage_avg.keys()):
                    baseline_coverage_avg[key] = (
                        baseline_coverage_avg[key] / len(baseline_coverages)
                    )
                combined_current = dict(pattern_stats)
                combined_current.update(coverage_stats)
                combined_baseline = dict(baseline_pattern_avg)
                combined_baseline.update(baseline_coverage_avg)
                deviation_score = compute_deviation_score(
                    combined_current, combined_baseline
                )
            maglev_history.append(maglev_stats)
            pattern_history.append(pattern_stats)
            coverage_history.append(coverage_stats)
            tuning = update_tuning_from_history(
                tuning, maglev_history, pattern_history, coverage_history
            )
            print(
                f"[MAGLEV] {case_id} score={maglev_score} deviation={deviation_score:.2f} "
                f"stats={maglev_stats} coverage={coverage_stats}"
            )
            meta_path.write_text(
                meta_path.read_text()
                + "\n"
                + "\n".join([f"maglev_{k}={v}" for k, v in maglev_stats.items()])
                + f"\nmaglev_score={maglev_score}\n"
                + "\n".join([f"pattern_{k}={v}" for k, v in pattern_stats.items()])
                + "\n"
                + "\n".join(
                    [f"coverage_{k}={v}" for k, v in coverage_stats.items()]
                )
                + f"\ndeviation_score={deviation_score:.2f}\n"
            )

        if is_crash(returncode, output):
            crashes += 1
            sanitized_output = output.replace("*/", "* /")
            with js_path.open("a", encoding="utf-8") as js_file:
                js_file.write("\n/*\nD8 OUTPUT\n")
                js_file.write(sanitized_output)
                js_file.write("\n*/\n")
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
