"""
Mini calculator "service" — traceable steps with error propagation.

Public API:
- evaluate(expr: str) -> number
- evaluate_with_trace(expr: str) -> (number, [steps...])

On ANY exception, we attach `e._trace_steps = steps` so the fuzzer can print
the attempted operations instead of "(no steps recorded)".
"""

import ast

MAX_LEN = 256
MAX_ABS_RESULT = 10**9

_ALLOWED_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod)
_ALLOWED_UNARY = (ast.UAdd, ast.USub)


class _Recorder:
    def __init__(self):
        self.steps = []
    def log(self, msg: str):
        self.steps.append(msg)


def _eval(node, rec: _Recorder):
    if isinstance(node, ast.Expression):
        return _eval(node.body, rec)

    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            rec.log(f"CONST {node.value!r}")
            return node.value
        raise ValueError("Only numeric constants allowed")

    if isinstance(node, ast.BinOp) and isinstance(node.op, _ALLOWED_BINOPS):
        left = _eval(node.left, rec)
        right = _eval(node.right, rec)

        if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
            raise ValueError("Operands must be numeric")

        if isinstance(node.op, ast.Add):
            res = left + right; rec.log(f"ADD  {left} + {right} = {res}"); return res
        if isinstance(node.op, ast.Sub):
            res = left - right; rec.log(f"SUB  {left} - {right} = {res}"); return res
        if isinstance(node.op, ast.Mult):
            res = left * right; rec.log(f"MUL  {left} * {right} = {res}"); return res
        if isinstance(node.op, ast.Div):
            res = left / right; rec.log(f"DIV  {left} / {right} = {res}"); return res
        if isinstance(node.op, ast.FloorDiv):
            res = left // right; rec.log(f"FDIV {left} // {right} = {res}"); return res
        if isinstance(node.op, ast.Mod):
            res = left % right; rec.log(f"MOD  {left} % {right} = {res}"); return res

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, _ALLOWED_UNARY):
        val = _eval(node.operand, rec)
        if not isinstance(val, (int, float)):
            raise ValueError("Operand must be numeric")
        if isinstance(node.op, ast.UAdd):
            res = +val; rec.log(f"UADD +{val} = {res}"); return res
        if isinstance(node.op, ast.USub):
            res = -val; rec.log(f"USUB -({val}) = {res}"); return res

    raise ValueError(f"Unsupported expression element: {type(node).__name__}")


def _raise_with_trace(exc: Exception, rec: _Recorder):
    try:
        setattr(exc, "_trace_steps", list(rec.steps))
    except Exception:
        pass
    raise exc


def evaluate_with_trace(expr: str):
    """Return (result, steps). On exception, attach `_trace_steps` and re-raise."""
    if not isinstance(expr, str):
        raise ValueError("Expression must be a string")
    expr = expr.strip()
    rec = _Recorder()

    if not expr:
        rec.log("ERROR Empty expression")
        return _raise_with_trace(ValueError("Empty expression"), rec)

    if len(expr) > MAX_LEN:
        rec.log(f"ERROR Expression too long: {len(expr)} > {MAX_LEN}")
        return _raise_with_trace(ValueError("Expression too long"), rec)

    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as se:
        rec.log("ERROR SyntaxError while parsing")
        return _raise_with_trace(se, rec)

    try:
        result = _eval(tree, rec)
    except Exception as e:
        return _raise_with_trace(e, rec)

    if isinstance(result, (int, float)) and abs(result) > MAX_ABS_RESULT:
        rec.log(f"ERROR Result out of bounds: {result}")
        return _raise_with_trace(ValueError("Result out of allowed bounds"), rec)

    rec.log(f"RESULT = {result}")
    return result, rec.steps


def evaluate(expr: str):
    """Compatibility wrapper used by non-tracing paths."""
    return evaluate_with_trace(expr)[0]
