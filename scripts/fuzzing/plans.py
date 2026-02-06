from __future__ import annotations

from collections import Counter
import random
import textwrap

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

ATTACK_TAGS = {attack["tag"] for attack in ATTACK_LIBRARY}
MUTATION_TAGS = {mutation["tag"] for mutation in MUTATION_LIBRARY}


def init_attack_weights() -> dict[str, float]:
    return {tag: 1.0 for tag in ATTACK_TAGS}


def init_mutation_weights() -> dict[str, float]:
    return {tag: 1.0 for tag in MUTATION_TAGS}


def update_attack_weights(
    weights: dict[str, float], stats: dict[str, int]
) -> dict[str, float]:
    next_weights = dict(weights)
    if stats["deopts"] < 2:
        for tag in ("proxy", "length", "holey"):
            next_weights[tag] = min(2.0, next_weights[tag] + 0.2)
    if stats["checkmaps"] > 8:
        next_weights["maps"] = min(2.0, next_weights["maps"] + 0.2)
    if stats["elements_transitions"] == 0:
        next_weights["typed"] = min(2.0, next_weights["typed"] + 0.2)
    if stats["checkbounds"] > 8:
        next_weights["length"] = min(2.0, next_weights["length"] + 0.2)
    return next_weights


def update_mutation_weights(
    weights: dict[str, float], stats: dict[str, int]
) -> dict[str, float]:
    next_weights = dict(weights)
    if stats["deopts"] < 2:
        for tag in ("proxy", "length", "holey"):
            next_weights[tag] = min(2.0, next_weights[tag] + 0.2)
    if stats["checkmaps"] > 8:
        next_weights["maps"] = min(2.0, next_weights["maps"] + 0.2)
    if stats["elements_transitions"] == 0:
        next_weights["typed"] = min(2.0, next_weights["typed"] + 0.2)
    if stats["checkbounds"] > 8:
        next_weights["length"] = min(2.0, next_weights["length"] + 0.2)
    return next_weights


def build_attack_plan(
    rng: random.Random,
    attack_count: int,
    attack_weights: dict[str, float],
) -> tuple[str, list[str]]:
    weighted_ops: list[tuple[dict[str, str], float]] = []
    for attack in ATTACK_LIBRARY:
        weight = attack_weights.get(attack["tag"], 1.0)
        weighted_ops.append((attack, weight))

    selections: list[dict[str, str]] = []
    for _ in range(attack_count):
        choices = [op for op, _ in weighted_ops]
        weights = [w for _, w in weighted_ops]
        selections.append(rng.choices(choices, weights=weights, k=1)[0])

    rendered = []
    for attack in selections:
        code = textwrap.dedent(attack["code"]).strip()
        rendered.append(
            "  function(slot, target) {\n"
            + textwrap.indent(code, " " * 4)
            + "\n  }"
        )
    return ",\n".join(rendered), [attack["name"] for attack in selections]


def build_mutation_plan(
    rng: random.Random,
    mutation_count: int,
    mutation_weights: dict[str, float],
) -> tuple[str, list[str]]:
    weighted_ops: list[tuple[dict[str, str], float]] = []
    for mutation in MUTATION_LIBRARY:
        weight = mutation_weights.get(mutation["tag"], 1.0)
        weighted_ops.append((mutation, weight))

    selections: list[dict[str, str]] = []
    for _ in range(mutation_count):
        choices = [op for op, _ in weighted_ops]
        weights = [w for _, w in weighted_ops]
        selections.append(rng.choices(choices, weights=weights, k=1)[0])

    rendered = []
    for mutation in selections:
        code = textwrap.dedent(mutation["code"]).strip()
        rendered.append(
            "  function(target, i) {\n"
            + textwrap.indent(code, " " * 4)
            + "\n  }"
        )
    return ",\n".join(rendered), [mutation["name"] for mutation in selections]
