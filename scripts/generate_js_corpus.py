#!/usr/bin/env python3
"""
Generate a large JavaScript corpus for V8 fuzzing.
Each file includes a header with suggested d8 flags and a seed ID.
"""

import argparse
import random
from pathlib import Path

FLAG_SETS = {
    "oob": [
        "--allow-natives-syntax",
        "--expose-gc",
        "--no-concurrent-gc",
        "--no-lazy-feedback-allocation",
        "--verify-heap",
    ],
    "typed-array": [
        "--allow-natives-syntax",
        "--expose-gc",
        "--turbo-fast-api-calls",
        "--no-concurrent-gc",
    ],
    "jit": [
        "--allow-natives-syntax",
        "--expose-gc",
        "--trace-turbo",
        "--trace-deopt",
        "--maglev",
        "--print-maglev-graph",
    ],
    "wasm": [
        "--allow-natives-syntax",
        "--expose-gc",
        "--wasm-staging",
        "--no-concurrent-gc",
    ],
    "gc": [
        "--allow-natives-syntax",
        "--expose-gc",
        "--stress-scavenge",
        "--stress-compaction",
    ],
}

TEMPLATES = []

TEMPLATES.append(
    (
        "oob_proxy",
        r"""
function vulnerableRead(arr) {
  let len = arr.length;
  return arr[len + {oob_offset}];
}

let stable = [];
for (let i = 0; i < {warmup}; i++) stable[i] = i * 1.25;
for (let i = 0; i < {pre_opt}; i++) vulnerableRead(stable);

%PrepareFunctionForOptimization(vulnerableRead);
for (let i = 0; i < {opt_calls}; i++) vulnerableRead(stable);
%OptimizeFunctionOnNextCall(vulnerableRead);
vulnerableRead(stable);

let victim = [1.1, 2.2, 3.3, 4.4, 5.5];
delete victim[2];

let proxy = new Proxy(victim, {
  get(target, prop, receiver) {
    if (prop === 'length') {
      gc(); gc();
      for (let i = 0; i < {reallocs}; i++) target.push(10 + i);
      target[0] = {{ptr: 0x41414141}};
      target.length = {shrink_len};
      return {fake_length};
    }
    return Reflect.get(target, prop, receiver);
  }
});

for (let i = 0; i < {iterations}; i++) {
  try {
    let val = vulnerableRead(proxy);
    if (val && typeof val === 'object') Object.keys(val);
  } catch (e) {}
  if (i % {outer_gc_interval} === 0) gc();
}
""",
        "oob",
    )
)

TEMPLATES.append(
    (
        "typed_array_views",
        r"""
let buffer = new ArrayBuffer({buf_size});
let u8 = new Uint8Array(buffer);
let f64 = new Float64Array(buffer);

for (let i = 0; i < u8.length; i++) u8[i] = i & 0xff;

function hammer(view) {
  let sum = 0;
  for (let i = 0; i < {iters}; i++) {
    let idx = (i * {stride}) % view.length;
    sum += view[idx];
  }
  return sum;
}

%PrepareFunctionForOptimization(hammer);
for (let i = 0; i < {warmup}; i++) hammer(u8);
%OptimizeFunctionOnNextCall(hammer);
hammer(u8);

let dv = new DataView(buffer);
let offset = {offset};
try {
  dv.setFloat64(offset, 13.37, true);
  dv.getFloat64(offset, true);
} catch (e) {}

print('sum=' + hammer(u8));
""",
        "typed-array",
    )
)

TEMPLATES.append(
    (
        "elements_kind_transition",
        r"""
function transition(arr) {
  let sum = 0;
  for (let i = 0; i < arr.length; i++) sum += arr[i];
  return sum;
}

let arr = [1.1, 2.2, 3.3, 4.4];
for (let i = 0; i < {warmup}; i++) transition(arr);

%PrepareFunctionForOptimization(transition);
for (let i = 0; i < {opt_calls}; i++) transition(arr);
%OptimizeFunctionOnNextCall(transition);
transition(arr);

arr[{hole_index}] = undefined;
arr.push({{x: 1}});
arr[{hole_index}] = 13.37;

print('sum=' + transition(arr));
""",
        "jit",
    )
)

TEMPLATES.append(
    (
        "proto_chain",
        r"""
function readProp(obj) {
  return obj.prop + 1;
}

let base = {{prop: 1}};
let mid = Object.create(base);
let leaf = Object.create(mid);

for (let i = 0; i < {warmup}; i++) readProp(leaf);
%PrepareFunctionForOptimization(readProp);
for (let i = 0; i < {opt_calls}; i++) readProp(leaf);
%OptimizeFunctionOnNextCall(readProp);
readProp(leaf);

Object.setPrototypeOf(leaf, {{prop: 100}});
Object.defineProperty(mid, 'prop', {{get() {{ return {getter_val}; }}}});

print('val=' + readProp(leaf));
""",
        "jit",
    )
)

TEMPLATES.append(
    (
        "wasm_bounds",
        r"""
let wasmBytes = new Uint8Array([0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00]);
let module = new WebAssembly.Module(wasmBytes);
let instance = new WebAssembly.Instance(module, {{}});

let mem = new WebAssembly.Memory({{initial: 1}});
let u8 = new Uint8Array(mem.buffer);

for (let i = 0; i < {iters}; i++) {
  let idx = (i * {stride}) & (u8.length - 1);
  u8[idx] = i & 0xff;
}
print('wasm=' + u8[0]);
""",
        "wasm",
    )
)

TEMPLATES.append(
    (
        "gc_pressure",
        r"""
let objs = [];
for (let i = 0; i < {count}; i++) {{
  objs.push({{idx: i, data: new Array({pad}).fill(i)}});
  if (i % {gc_every} === 0) gc();
}}

function churn() {{
  let tmp = [];
  for (let i = 0; i < {iters}; i++) tmp.push({{i}});
  return tmp.length;
}}

%PrepareFunctionForOptimization(churn);
for (let i = 0; i < {warmup}; i++) churn();
%OptimizeFunctionOnNextCall(churn);
print('churn=' + churn());
""",
        "gc",
    )
)


def render_case(template: str, rng: random.Random) -> str:
    params = {
        "oob_offset": rng.randint(16, 300),
        "warmup": rng.randint(100, 2000),
        "pre_opt": rng.randint(200, 5000),
        "opt_calls": rng.randint(20, 200),
        "reallocs": rng.randint(5, 80),
        "shrink_len": rng.randint(1, 4),
        "fake_length": rng.randint(32, 256),
        "iterations": rng.randint(30, 200),
        "outer_gc_interval": rng.randint(1, 5),
        "buf_size": rng.randint(256, 8192),
        "iters": rng.randint(200, 5000),
        "stride": rng.randint(3, 64),
        "offset": rng.choice([0, 1, 2, 4, 8, 16, 24]),
        "hole_index": rng.randint(0, 3),
        "getter_val": rng.randint(10, 200),
        "count": rng.randint(100, 2000),
        "pad": rng.randint(10, 80),
        "gc_every": rng.randint(10, 50),
    }
    return template.format(**params)


def write_case(out_dir: Path, case_id: int, rng: random.Random) -> None:
    name, template, flag_key = rng.choice(TEMPLATES)
    flags = " ".join(FLAG_SETS[flag_key])
    js_body = render_case(template, rng)
    header = "\n".join(
        [
            "// === V8 FUZZ CASE ===",
            f"// id: {case_id}",
            f"// template: {name}",
            f"// suggested_d8_flags: {flags}",
            "// =====================",
            "",
        ]
    )

    out_path = out_dir / f"case_{case_id:05d}_{name}.js"
    out_path.write_text(header + js_body)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate JS corpus for V8 fuzzing")
    parser.add_argument("--out", default="corpus", help="Output directory")
    parser.add_argument("--count", type=int, default=10000, help="Number of JS files")
    parser.add_argument("--seed", type=int, default=1337, help="Random seed")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(args.seed)

    for case_id in range(1, args.count + 1):
        write_case(out_dir, case_id, rng)

    print(f"Wrote {args.count} JS files to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
