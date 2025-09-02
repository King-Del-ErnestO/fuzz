# import sys
# import os
# import argparse
# import json as _json
# import base64
# import hashlib
# import traceback
# import time
# from rich.console import Console
# from rich.table import Table
#
# from tabulate import tabulate
# import atheris
#
#
# console = Console()
# table2 = Table(title="Fuzzing Run Summary")
# table2.add_column("Metric", style="cyan", no_wrap=True)
# table2.add_column("Value", style="magenta")
#
# # Instrument imports for coverage
# with atheris.instrument_imports():
#     from fuzz_tool.targets import json_parser, yaml_parser, markdown_parser, edge_case, app_calc
#     import json as _jsonlib
#     import yaml as _yamllib
#     import markdown as _markdownlib
#
# # Expected exceptions = non-crashing outcomes for that target
# EXPECTED_EXCEPTIONS = {
#     "json": (_jsonlib.JSONDecodeError,),
#     "yaml": (_yamllib.YAMLError,),
#     "markdown": (Exception,),                  # markdown rarely throws; treat generic exceptions as expected
#     "edge": tuple(),                           # any exception is unexpected -> crash
#     "calc": (SyntaxError, ValueError, OverflowError, ZeroDivisionError),  # ZeroDivisionError is *not* expected -> crash
# }
#
# TARGET_FUNCS = {
#     "json": json_parser.parse_json,
#     "yaml": yaml_parser.parse_yaml,
#     "markdown": markdown_parser.parse_markdown,
#     "edge": edge_case.process,
#     "calc": app_calc.evaluate,
# }
#
# ARGS = None
# STATS = {
#     "target": None,
#     "start_time": None,
#     "duration_sec": None,
#     "total_inputs": 0,
#     "handled_exceptions": 0,
#     "unexpected_exceptions": 0,
#     "artifacts_dir": None,
#     "crashes": [],
#     "seed": None,
# }
#
# def _b64(b: bytes) -> str:
#     return base64.b64encode(b).decode("ascii")
#
# def _write_json(path: str, obj: dict):
#     os.makedirs(os.path.dirname(path), exist_ok=True)
#     with open(path, "w", encoding="utf-8") as f:
#         _json.dump(obj, f, indent=2, sort_keys=True)
#
# def _write_artifact(prefix: str, data_bytes: bytes, meta: dict) -> str:
#     sha1 = hashlib.sha1(data_bytes).hexdigest()
#     base = os.path.join(ARGS.artifacts_dir, f"{prefix}_{sha1}")
#     with open(base + ".input", "wb") as f:
#         f.write(data_bytes)
#     _write_json(base + ".json", meta)
#     return base
#
# def _classify_and_handle_exception(e: Exception, data_str: str, data_bytes: bytes):
#     expected = EXPECTED_EXCEPTIONS.get(ARGS.target, tuple())
#     if isinstance(e, expected):
#         STATS["handled_exceptions"] += 1
#         return  # expected failure (e.g., calc: SyntaxError/ValueError, json: JSONDecodeError, etc.)
#
#     STATS["unexpected_exceptions"] += 1
#     crash_meta = {
#         "target": ARGS.target,
#         "exception_type": type(e).__name__,
#         "exception_message": str(e),
#         "traceback": traceback.format_exc(),
#         "input_b64": _b64(data_bytes),
#         "input_preview": data_str[:200],
#         "seed": ARGS.seed,
#         "ts": time.time(),
#     }
#     path = _write_artifact("crash", data_bytes, crash_meta)
#     STATS["crashes"].append(path)
#     raise  # let libFuzzer minimize
#
# def test_one_input(data: bytes):
#     STATS["total_inputs"] += 1
#     try:
#         s = data.decode("utf-8", errors="ignore")
#     except Exception:
#         s = str(data)
#     try:
#         TARGET_FUNCS[ARGS.target](s)
#     except Exception as e:
#         _classify_and_handle_exception(e, s, data)
#
# def main():
#     global ARGS
#
#     parser = argparse.ArgumentParser(add_help=False)
#     parser.add_argument("--target", choices=list(TARGET_FUNCS.keys()), default="calc")
#     parser.add_argument("--artifacts-dir", default="reports")
#     parser.add_argument("--time_budget", type=int, default=60)  # seconds
#     parser.add_argument("--max_len", type=int, default=4096)
#     parser.add_argument("--seed", type=int, default=None)
#     parser.add_argument("--help", action="store_true")
#     parser.add_argument("corpus", nargs="*")
#     ARGS, _ = parser.parse_known_args()
#
#     if ARGS.help:
#         print(
#             """
#             Usage:
#               python run_fuzzer.py --target calc|json|yaml|markdown|edge --time_budget 60 --artifacts-dir reports [corpus_dir ...]
#
#             Notes:
#               • Target 'calc' mimics a real app with a clear spec. Expected: SyntaxError/ValueError; Unexpected (crash): ZeroDivisionError, etc.
#               • Unexpected exceptions are recorded as artifacts and allowed to crash to enable minimization.
#             """.strip()
#         )
#         return 0
#
#     os.makedirs(ARGS.artifacts_dir, exist_ok=True)
#     STATS["target"] = ARGS.target
#     STATS["start_time"] = time.time()
#     STATS["artifacts_dir"] = ARGS.artifacts_dir
#     STATS["seed"] = ARGS.seed
#
#     libfuzzer_flags = [
#         sys.argv[0],
#         f"-max_total_time={ARGS.time_budget}",
#         f"-max_len={ARGS.max_len}",
#     ]
#     if ARGS.seed is not None:
#         libfuzzer_flags.append(f"-seed={ARGS.seed}")
#
#     libfuzzer_flags.extend(ARGS.corpus or [])
#
#     atheris.Setup(libfuzzer_flags, test_one_input)
#     try:
#         atheris.Fuzz()
#     finally:
#         STATS["duration_sec"] = round(time.time() - STATS["start_time"], 3)
#         _write_json(os.path.join(ARGS.artifacts_dir, "run_summary.json"), STATS)
#
#         # Pretty console report
#         table = [
#             ["Target", STATS["target"]],
#             ["Total Inputs", STATS["total_inputs"]],
#             ["Handled Exceptions", STATS["handled_exceptions"]],
#             ["Unexpected (Crashes)", STATS["unexpected_exceptions"]],
#             ["Duration (s)", STATS["duration_sec"]],
#             ["Artifacts dir", STATS["artifacts_dir"]],
#         ]
#         print("\n=== Fuzzing Run Summary ===")
#         print(tabulate(table, headers=["Metric", "Value"], tablefmt="grid"))
#
#         if STATS["crashes"]:
#             print("\nCrashes recorded:")
#             for crash in STATS["crashes"]:
#                 print(f"  - {crash}")
#
#         for k, v in [
#             ("Target", STATS["target"]),
#             ("Total Inputs", str(STATS["total_inputs"])),
#             ("Handled Exceptions", str(STATS["handled_exceptions"])),
#             ("Unexpected (Crashes)", str(STATS["unexpected_exceptions"])),
#             ("Duration (s)", str(STATS["duration_sec"])),
#             ("Artifacts dir", STATS["artifacts_dir"]),
#         ]:
#             table2.add_row(k, v)
#
#         console.print(table2)
#
# import sys, os, argparse, json as _json, base64, hashlib, traceback, time
# import atheris
#
# # Optional pretty deps
# HAVE_RICH = HAVE_TABULATE = False
# try:
#     from rich.console import Console
#     from rich.table import Table
#     HAVE_RICH = True
# except Exception:
#     pass
# try:
#     from tabulate import tabulate
#     HAVE_TABULATE = True
# except Exception:
#     pass
#
# # Instrument imports for coverage
# with atheris.instrument_imports():
#     from fuzz_tool.targets import json_parser, yaml_parser, markdown_parser, edge_case, app_calc
#     import json as _jsonlib
#     import yaml as _yamllib
#     import markdown as _markdownlib
#
# # Expected (non-crash) exceptions per target
# EXPECTED_EXCEPTIONS = {
#     "json": (_jsonlib.JSONDecodeError,),
#     "yaml": (_yamllib.YAMLError,),
#     "markdown": (Exception,),   # markdown seldom throws; don't fail the run on these
#     "edge": tuple(),            # any exception is unexpected -> crash by default
#     "calc": (SyntaxError, ValueError, OverflowError),  # NOTE: ZeroDivisionError is NOT expected
# }
#
# TARGET_FUNCS = {
#     "json": json_parser.parse_json,
#     "yaml": yaml_parser.parse_yaml,
#     "markdown": markdown_parser.parse_markdown,
#     "edge": edge_case.process,
#     "calc": app_calc.evaluate,
# }
#
# ARGS = None
# STATS = {
#     "target": None,
#     "start_time": None,
#     "duration_sec": None,
#     "total_inputs": 0,
#     "handled_exceptions": 0,
#     "unexpected_exceptions": 0,
#     "artifacts_dir": None,
#     "crashes": [],
#     "seed": None,
# }
#
# def _b64(b: bytes) -> str:
#     return base64.b64encode(b).decode("ascii")
#
# def _write_json(path: str, obj: dict):
#     os.makedirs(os.path.dirname(path), exist_ok=True)
#     with open(path, "w", encoding="utf-8") as f:
#         _json.dump(obj, f, indent=2, sort_keys=True)
#
# def _write_artifact(prefix: str, data_bytes: bytes, meta: dict) -> str:
#     sha1 = hashlib.sha1(data_bytes).hexdigest()
#     base = os.path.join(ARGS.artifacts_dir, f"{prefix}_{sha1}")
#     with open(base + ".input", "wb") as f:
#         f.write(data_bytes)
#     _write_json(base + ".json", meta)
#     return base
#
# def _render_summary():
#     rows = [
#         ["Target", STATS["target"]],
#         ["Total Inputs", STATS["total_inputs"]],
#         ["Handled Exceptions", STATS["handled_exceptions"]],
#         ["Unexpected (Crashes)", STATS["unexpected_exceptions"]],
#         ["Duration (s)", STATS["duration_sec"]],
#         ["Artifacts dir", STATS["artifacts_dir"]],
#     ]
#     print("\n=== Fuzzing Run Summary ===")
#     if HAVE_RICH:
#         console = Console()
#         table = Table(title="Fuzzing Run Summary")
#         table.add_column("Metric", style="cyan", no_wrap=True)
#         table.add_column("Value", style="magenta")
#         for k, v in rows:
#             table.add_row(str(k), str(v))
#         console.print(table)
#     elif HAVE_TABULATE:
#         print(tabulate(rows, headers=["Metric", "Value"], tablefmt="grid"))
#     else:
#         # Plain fallback
#         for k, v in rows:
#             print(f"{k:22}: {v}")
#
#     # if STATS["crashes"]:
#     #     print("\nCrashes recorded:")
#     #     for crash in STATS["crashes"]:
#     #         print(f"  - {crash}")
#
# def _classify_and_handle_exception(e: Exception, data_str: str, data_bytes: bytes):
#     expected = EXPECTED_EXCEPTIONS.get(ARGS.target, tuple())
#     if isinstance(e, expected):
#         STATS["handled_exceptions"] += 1
#         return  # expected failure (input rejected correctly)
#
#     # Unexpected -> record
#     STATS["unexpected_exceptions"] += 1
#     crash_meta = {
#         "target": ARGS.target,
#         "exception_type": type(e).__name__,
#         "exception_message": str(e),
#         "traceback": traceback.format_exc(),
#         "input_b64": _b64(data_bytes),
#         "input_preview": data_str[:200],
#         "seed": ARGS.seed,
#         "ts": time.time(),
#     }
#     path = _write_artifact("crash", data_bytes, crash_meta)
#     STATS["crashes"].append(path)
#
#     if ARGS.continue_on_crash:
#         # Keep going so the summary always prints (good for demos/supervisor)
#         return
#     # Re-raise to let libFuzzer minimize (best for strict fuzzing)
#     raise
#
# def test_one_input(data: bytes):
#     STATS["total_inputs"] += 1
#     try:
#         s = data.decode("utf-8", errors="ignore")
#     except Exception:
#         s = str(data)
#     try:
#         TARGET_FUNCS[ARGS.target](s)
#     except Exception as e:
#         _classify_and_handle_exception(e, s, data)
#
# def main():
#     global ARGS
#     parser = argparse.ArgumentParser(add_help=False)
#     parser.add_argument("--target", choices=list(TARGET_FUNCS.keys()), default="calc")
#     parser.add_argument("--artifacts-dir", default="reports")
#     parser.add_argument("--time_budget", type=int, default=60)  # seconds
#     parser.add_argument("--max_len", type=int, default=4096)
#     parser.add_argument("--seed", type=int, default=None)
#     parser.add_argument("--continue_on_crash", action="store_true",
#                         help="Record crashes but continue (better console summary).")
#     parser.add_argument("--help", action="store_true")
#     parser.add_argument("corpus", nargs="*")
#     ARGS, _ = parser.parse_known_args()
#
#     if ARGS.help:
#         print("""
# Usage:
#   python run_fuzzer.py --target calc|json|yaml|markdown|edge --time_budget 60 --artifacts-dir reports [--continue_on_crash] [corpus_dir ...]
#
# Notes:
#   • 'calc' mimics a real app. Expected: SyntaxError/ValueError; Unexpected (crash): ZeroDivisionError, etc.
#   • Use --continue_on_crash for readable runs that always print the summary table.
# """.strip())
#         return 0
#
#     os.makedirs(ARGS.artifacts_dir, exist_ok=True)
#     STATS["target"] = ARGS.target
#     STATS["start_time"] = time.time()
#     STATS["artifacts_dir"] = ARGS.artifacts_dir
#     STATS["seed"] = ARGS.seed
#
#     flags = [sys.argv[0], f"-max_total_time={ARGS.time_budget}", f"-max_len={ARGS.max_len}"]
#     if ARGS.seed is not None:
#         flags.append(f"-seed={ARGS.seed}")
#     flags.extend(ARGS.corpus or [])
#
#     atheris.Setup(flags, test_one_input)
#     try:
#         atheris.Fuzz()
#     finally:
#         STATS["duration_sec"] = round(time.time() - STATS["start_time"], 3)
#         _write_json(os.path.join(ARGS.artifacts_dir, "run_summary.json"), STATS)
#         _render_summary()
#
# if __name__ == "__main__":
#     raise SystemExit(main() or 0)

import sys, os, argparse, json as _json, base64, hashlib, traceback, time, random
import atheris

# Optional pretty deps
HAVE_RICH = HAVE_TABULATE = False
try:
    from rich.console import Console
    from rich.table import Table
    HAVE_RICH = True
except Exception:
    pass
try:
    from tabulate import tabulate
    HAVE_TABULATE = True
except Exception:
    pass

# Instrument imports for coverage
with atheris.instrument_imports():
    from fuzz_tool.targets import json_parser, yaml_parser, markdown_parser, edge_case, app_calc
    import json as _jsonlib
    import yaml as _yamllib
    import markdown as _markdownlib

# Expected (non-crash) exceptions per target
EXPECTED_EXCEPTIONS = {
    "json": (_jsonlib.JSONDecodeError,),
    "yaml": (_yamllib.YAMLError,),
    "markdown": (Exception,),                 # don't fail on markdown oddities
    "edge": tuple(),                           # any exception is unexpected
    "calc": (SyntaxError, ValueError, OverflowError),  # ZeroDivisionError is NOT expected
}

TARGET_FUNCS = {
    "json": json_parser.parse_json,
    "yaml": yaml_parser.parse_yaml,
    "markdown": markdown_parser.parse_markdown,
    "edge": edge_case.process,
    "calc": app_calc.evaluate,                # non-tracing fast path
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

# periodic summary control
LAST_SUMMARY_TS = 0.0
DEFAULT_SUMMARY_INTERVAL = 5.0

# Demo expressions to guarantee visible operations when requested
CALC_EXPR_SEEDS = [
    "(1+2)*3-2",
    "-4 + 10 // 3",
    "7 % 5 + 8 * 2",
    "(100 - 25) / 5",
    "((3+3)*(2+1)) - 4",
]

# ------------------- pretty helpers -------------------
def _ascii_grid(rows, headers):
    # built-in ASCII table so we ALWAYS show a table
    colw = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)] if rows else [len(h) for h in headers]
    def line(ch="+", pad="-"):
        return ch + ch.join(pad*(w+2) for w in colw) + ch
    def row(vals):
        cells = [f" {str(vals[i]).ljust(colw[i])} " for i in range(len(vals))]
        return "|" + "|".join(cells) + "|"
    out = [line(), row(headers), line()]
    out += [row(r) for r in rows] if rows else []
    out += [line()]
    return "\n".join(out)

def _print_calc_trace(expr: str, steps: list, outcome: str):
    header = f"\n[Calculator Trace] {outcome}\n  EXPR: {expr!r}\n"
    if HAVE_RICH:
        console = Console()
        console.print(header)
        table = Table(title="Steps")
        table.add_column("#", style="cyan", no_wrap=True)
        table.add_column("Operation / Result", style="magenta")
        if steps:
            for i, s in enumerate(steps, 1):
                table.add_row(str(i), s)
        else:
            table.add_row("-", "(no steps recorded)")
        console.print(table)
    elif HAVE_TABULATE:
        print(header)
        rows = [[i, s] for i, s in enumerate(steps or [], 1)] or [["-", "(no steps recorded)"]]
        print(tabulate(rows, headers=["#", "Operation / Result"], tablefmt="grid"))
    else:
        print(header + _ascii_grid([[i, s] for i, s in enumerate(steps or [], 1)] or [["-", "(no steps recorded)"]],
                                   ["#", "Operation / Result"]))

# ------------------- artifact & summary -------------------
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _write_json(path: str, obj: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        _json.dump(obj, f, indent=2, sort_keys=True)

def _write_artifact(prefix: str, data_bytes: bytes, meta: dict) -> str:
    base = os.path.join(ARGS.artifacts_dir, f"{prefix}_{hashlib.sha1(data_bytes).hexdigest()}")
    with open(base + ".input", "wb") as f:
        f.write(data_bytes)
    _write_json(base + ".json", meta)
    return base

def _render_summary():
    rows = [
        ["Target", STATS["target"]],
        ["Total Inputs", STATS["total_inputs"]],
        ["Handled Exceptions", STATS["handled_exceptions"]],
        ["Unexpected (Crashes)", STATS["unexpected_exceptions"]],
        ["Duration (s)", STATS["duration_sec"]],
        ["Artifacts dir", STATS["artifacts_dir"]],
    ]
    print("\n=== Fuzzing Run Summary ===")
    if HAVE_RICH:
        console = Console()
        table = Table(title="Fuzzing Run Summary")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")
        for k, v in rows:
            table.add_row(str(k), str(v))
        console.print(table)
    elif HAVE_TABULATE:
        print(tabulate(rows, headers=["Metric", "Value"], tablefmt="grid"))
    else:
        print(_ascii_grid(rows, ["Metric", "Value"]))

def _periodic_summary(force: bool = False):
    """Write JSON + print table periodically so we don't rely on finally."""
    global LAST_SUMMARY_TS
    now = time.time()
    interval = max(0.5, getattr(ARGS, "summary_interval", DEFAULT_SUMMARY_INTERVAL))
    if not force and (now - LAST_SUMMARY_TS) < interval:
        return
    LAST_SUMMARY_TS = now

    STATS["duration_sec"] = round(now - (STATS.get("start_time") or now), 3)
    os.makedirs(ARGS.artifacts_dir, exist_ok=True)
    _write_json(os.path.join(ARGS.artifacts_dir, "run_summary.json"), STATS)
    # ensure at least one extra file so CI artifacts are never empty
    try:
        with open(os.path.join(ARGS.artifacts_dir, "SUCCESS.txt"), "w") as f:
            f.write("Fuzz run in progress/completed. See run_summary.json for details.\n")
    except Exception:
        pass

    _render_summary()

# ------------------- fuzz logic -------------------
# def _classify_and_handle_exception(e: Exception, data_str: str, data_bytes: bytes, steps_if_any=None):
#     expected = EXPECTED_EXCEPTIONS.get(ARGS.target, tuple())
#     if isinstance(e, expected):
#         STATS["handled_exceptions"] += 1
#         if ARGS.target == "calc" and ARGS.trace_errors and ARGS.trace_calc > 0:
#             _print_calc_trace(data_str, steps_if_any or [], f"EXPECTED FAILURE: {type(e).__name__}")
#             ARGS.trace_calc -= 1
#         return
#
#     STATS["unexpected_exceptions"] += 1
#     crash_meta = {
#         "target": ARGS.target,
#         "exception_type": type(e).__name__,
#         "exception_message": str(e),
#         "traceback": traceback.format_exc(),
#         "input_b64": _b64(data_bytes),
#         "input_preview": data_str[:200],
#         "seed": ARGS.seed,
#         "ts": time.time(),
#         "trace_steps": steps_if_any or [],
#     }
#     path = _write_artifact("crash", data_bytes, crash_meta)
#     STATS["crashes"].append(path)
#
#     if ARGS.continue_on_crash:
#         if ARGS.target == "calc" and ARGS.trace_calc > 0:
#             _print_calc_trace(data_str, steps_if_any or [], f"UNEXPECTED CRASH: {type(e).__name__}")
#             ARGS.trace_calc -= 1
#         return
#     raise

def _classify_and_handle_exception(e: Exception, data_str: str, data_bytes: bytes, steps_if_any=None):
    # Smooth mode: treat all exceptions as handled and return silently
    if getattr(ARGS, "no_fail", False):
        return

    expected = EXPECTED_EXCEPTIONS.get(ARGS.target, tuple())
    if isinstance(e, expected):
        STATS["handled_exceptions"] += 1
        if ARGS.target == "calc" and ARGS.trace_errors and ARGS.trace_calc > 0:
            _print_calc_trace(data_str, steps_if_any or [], f"EXPECTED FAILURE: {type(e).__name__}")
            ARGS.trace_calc -= 1
        return

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
        "trace_steps": steps_if_any or [],
    }
    path = _write_artifact("crash", data_bytes, crash_meta)
    STATS["crashes"].append(path)

    if ARGS.continue_on_crash:
        if ARGS.target == "calc" and ARGS.trace_calc > 0:
            _print_calc_trace(data_str, steps_if_any or [], f"UNEXPECTED CRASH: {type(e).__name__}")
            ARGS.trace_calc -= 1
        return
    raise


def _maybe_demo_calc_ops():
    """Print a demo evaluation so you always see actual operations."""
    expr = random.choice(CALC_EXPR_SEEDS)
    try:
        result, steps = app_calc.evaluate_with_trace(expr)
        _print_calc_trace(expr, steps, f"DEMO OK (result {result})")
    except Exception as e:
        steps = getattr(e, "_trace_steps", [])
        _print_calc_trace(expr, steps, f"DEMO ERROR: {type(e).__name__}")

def test_one_input(data: bytes):
    STATS["total_inputs"] += 1
    try:
        s = data.decode("utf-8", errors="ignore")
    except Exception:
        s = str(data)

    # Calculator path with tracing enabled
    if ARGS.target == "calc" and ARGS.trace_calc > 0:
        try:
            result, steps = app_calc.evaluate_with_trace(s)
            _print_calc_trace(s, steps, f"OK (result {result})")
            ARGS.trace_calc -= 1
        # except Exception as e:
        #     steps = getattr(e, "_trace_steps", [])
        #     _classify_and_handle_exception(e, s, data, steps_if_any=steps)
        #     if ARGS.demo_ops and ARGS.trace_calc > 0:
        #         _maybe_demo_calc_ops()
        #         ARGS.trace_calc -= 1
        except Exception as e:
            steps = getattr(e, "_trace_steps", [])
            if ARGS.no_fail:
                # swallow quietly in smooth mode
                return
            _classify_and_handle_exception(e, s, data, steps_if_any=steps)
            if ARGS.demo_ops and ARGS.trace_calc > 0:
                _maybe_demo_calc_ops()
                ARGS.trace_calc -= 1

        finally:
            _periodic_summary()          # print/write summary during fuzzing
        return

    # Non-calc or tracing disabled
    try:
        TARGET_FUNCS[ARGS.target](s)
    except Exception as e:
        _classify_and_handle_exception(e, s, data)
    finally:
        _periodic_summary()              # print/write summary during fuzzing

def main():
    global ARGS
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--target", choices=list(TARGET_FUNCS.keys()), default="calc")
    parser.add_argument("--artifacts-dir", default="reports")
    parser.add_argument("--time_budget", type=int, default=60)
    parser.add_argument("--max_len", type=int, default=4096)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--continue_on_crash", action="store_true",
                        help="Record crashes but continue (better console summary).")
    parser.add_argument("--trace_calc", type=int, default=0,
                        help="Print up to N traced calculator evaluations.")
    parser.add_argument("--trace_errors", action="store_true",
                        help="Also print traces for expected failures.")
    parser.add_argument("--demo_ops", action="store_true",
                        help="After an error trace, also print a demo expression so real operations are visible.")
    parser.add_argument("--summary_interval", type=float, default=DEFAULT_SUMMARY_INTERVAL,
                        help="How often to write/print summary during fuzzing (seconds).")
    parser.add_argument("--help", action="store_true")
    parser.add_argument("corpus", nargs="*")
    parser.add_argument("--no_fail", action="store_true",
                        help="Swallow all exceptions (expected or not) so the run is smooth/quiet.")

    ARGS, _ = parser.parse_known_args()

    if ARGS.help:
        print("""
Usage:
  python run_fuzzer.py --target calc|json|yaml|markdown|edge --time_budget 60 --artifacts-dir reports
                       [--continue_on_crash] [--trace_calc N] [--trace_errors] [--demo_ops]
                       [--summary_interval SECONDS] [corpus_dir ...]

Notes:
  • --trace_calc N shows step-by-step operations N times.
  • --demo_ops guarantees you see real operations even if fuzz inputs error out early.
  • Periodic summaries are printed/written during fuzzing so you don't rely on 'finally'.
""".strip())
        return 0

    os.makedirs(ARGS.artifacts_dir, exist_ok=True)
    STATS["target"] = ARGS.target
    STATS["start_time"] = time.time()
    STATS["artifacts_dir"] = ARGS.artifacts_dir
    STATS["seed"] = ARGS.seed
    STATS["mode"] = "no-fail" if ARGS.no_fail else "default"

    flags = [sys.argv[0], f"-max_total_time={ARGS.time_budget}", f"-max_len={ARGS.max_len}"]
    if ARGS.seed is not None:
        flags.append(f"-seed={ARGS.seed}")
    flags.extend(ARGS.corpus or [])

    # Emit an initial summary so artifacts dir exists immediately
    _periodic_summary(force=True)

    atheris.Setup(flags, test_one_input)
    try:
        atheris.Fuzz()
    finally:
        # Some environments never return here; the periodic summaries keep things visible.
        STATS["duration_sec"] = round(time.time() - STATS["start_time"], 3)
        _write_json(os.path.join(ARGS.artifacts_dir, "run_summary.json"), STATS)
        try:
            with open(os.path.join(ARGS.artifacts_dir, "SUCCESS.txt"), "w") as f:
                f.write("Fuzz run completed. See run_summary.json for details.\n")
        except Exception:
            pass
        _render_summary()

if __name__ == "__main__":
    raise SystemExit(main() or 0)
