# Ai_fuzzingns

This repo provides a small harness to fuzz V8's `d8` binary using an aggressive
out-of-bounds template derived from the provided exploit-style JavaScript.

## Quick start

1. Download a `d8` binary (ARM ASAN build by default):

```bash
scripts/setup_v8.sh /content/v8
```

2. Run the fuzzer (pointing at your `d8` binary):

```bash
python3 scripts/fuzz_v8.py --d8 /content/v8/<path-to-d8> --iterations 100
```

Crashers (non-zero exit or crash markers) are kept in the `crashes/` directory
along with a `.meta` file of parameters and a `.log` file of output.
Non-crashing cases are discarded to keep the output small.

3. Optionally analyze crash logs for patterns:

```bash
python3 scripts/fuzz_v8.py --d8 /content/v8/<path-to-d8> --iterations 100 --analyze-crashes
```

4. Or analyze a single log file directly:

```bash
python3 scripts/analyze_d8_log.py crashes/<case>.log --report crashes/<case>.report
```

## Notes

- If you want to target a different `d8` build, pass your own URL to
  `scripts/setup_v8.sh` or skip it entirely and just set `--d8`.
- The fuzzer defaults to a high-aggression config and may consume significant
  CPU and memory.
