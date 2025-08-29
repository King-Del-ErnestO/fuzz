import sys
import os
import argparse
import json as _json
import base64
import hashlib
import traceback
import time

import atheris

# Instrument imports for coverage
with atheris.instrument_imports():
    from fuzz_tool.targets import json_parser, yaml_parser, markdown_parser, edge_case, app_calc
    import json as _jsonlib
    import yaml as _yamllib
    import markdown as _markdownlib

# Expected exceptions = non-crashing outcomes for that target
EXPECTED_EXCEPTIONS = {
    "json": (_jsonlib.JSONDecodeError,),
    "yaml": (_yamllib.YAMLError,),
    "markdown": (Exception,),                  # markdown rarely throws; treat generic exceptions as expected
    "edge": tuple(),                           # any exception is unexpected -> crash
    "calc": (SyntaxError, ValueError, OverflowError, ZeroDivisionError),  # ZeroDivisionError is *not* expected -> crash
}

TARGET_FUNCS = {
    "json": json_parser.parse_json,
    "yaml": yaml_parser.parse_yaml,
    "markdown": markdown_parser.parse_markdown,
    "edge": edge_case.process,
    "calc": app_calc.evaluate,
}

ARGS = None
STATS = {
    "target": None,
    "start_time": None,
    "duration_sec": None,
    "total_inputs": 0,
    "handled_exceptions": 0,
    "unexpected_exceptions": 0,
    "artifacts_dir": None,
    "crashes": [],
    "seed": None,
}

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _write_json(path: str, obj: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        _json.dump(obj, f, indent=2, sort_keys=True)

def _write_artifact(prefix: str, data_bytes: bytes, meta: dict) -> str:
    sha1 = hashlib.sha1(data_bytes).hexdigest()
    base = os.path.join(ARGS.artifacts_dir, f"{prefix}_{sha1}")
    with open(base + ".input", "wb") as f:
        f.write(data_bytes)
    _write_json(base + ".json", meta)
    return base

def _classify_and_handle_exception(e: Exception, data_str: str, data_bytes: bytes):
    expected = EXPECTED_EXCEPTIONS.get(ARGS.target, tuple())
    if isinstance(e, expected):
        STATS["handled_exceptions"] += 1
        return  # expected failure (e.g., calc: SyntaxError/ValueError, json: JSONDecodeError, etc.)

    STATS["unexpected_exceptions"] += 1
    crash_meta = {
        "target": ARGS.target,
        "exception_type": type(e).__name__,
        "exception_message": str(e),
        "traceback": traceback.format_exc(),
        "input_b64": _b64(data_bytes),
        "input_preview": data_str[:200],
        "seed": ARGS.seed,
        "ts": time.time(),
    }
    path = _write_artifact("crash", data_bytes, crash_meta)
    STATS["crashes"].append(path)
    raise  # let libFuzzer minimize

def test_one_input(data: bytes):
    STATS["total_inputs"] += 1
    try:
        s = data.decode("utf-8", errors="ignore")
    except Exception:
        s = str(data)
    try:
        TARGET_FUNCS[ARGS.target](s)
    except Exception as e:
        _classify_and_handle_exception(e, s, data)

def main():
    global ARGS

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--target", choices=list(TARGET_FUNCS.keys()), default="calc")
    parser.add_argument("--artifacts-dir", default="reports")
    parser.add_argument("--time_budget", type=int, default=60)  # seconds
    parser.add_argument("--max_len", type=int, default=4096)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--help", action="store_true")
    parser.add_argument("corpus", nargs="*")
    ARGS, _ = parser.parse_known_args()

    if ARGS.help:
        print(
            """
Usage:
  python run_fuzzer.py --target calc|json|yaml|markdown|edge --time_budget 60 --artifacts-dir reports [corpus_dir ...]

Notes:
  • Target 'calc' mimics a real app with a clear spec. Expected: SyntaxError/ValueError; Unexpected (crash): ZeroDivisionError, etc.
  • Unexpected exceptions are recorded as artifacts and allowed to crash to enable minimization.
            """.strip()
        )
        return 0

    os.makedirs(ARGS.artifacts_dir, exist_ok=True)
    STATS["target"] = ARGS.target
    STATS["start_time"] = time.time()
    STATS["artifacts_dir"] = ARGS.artifacts_dir
    STATS["seed"] = ARGS.seed

    libfuzzer_flags = [
        sys.argv[0],
        f"-max_total_time={ARGS.time_budget}",
        f"-max_len={ARGS.max_len}",
    ]
    if ARGS.seed is not None:
        libfuzzer_flags.append(f"-seed={ARGS.seed}")

    libfuzzer_flags.extend(ARGS.corpus or [])

    atheris.Setup(libfuzzer_flags, test_one_input)
    try:
        atheris.Fuzz()
    finally:
        STATS["duration_sec"] = round(time.time() - STATS["start_time"], 3)
        _write_json(os.path.join(ARGS.artifacts_dir, "run_summary.json"), STATS)
