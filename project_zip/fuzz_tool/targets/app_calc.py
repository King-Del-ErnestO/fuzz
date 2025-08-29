"""
A tiny calculator "service" to mimic a real application core being fuzz-tested.

Spec (business rules):
- Accepts expressions with integers, + - * / // % and unary +/- and parentheses.
- Only numbers and operators allowed; no names, calls, attrs, etc.
- Max input length: 256 chars; empty not allowed.
- Result magnitude must be <= 1e9, else ValueError (expected failure).
- Syntax errors and general validation errors -> ValueError or SyntaxError (expected failures).
- Division by zero -> ZeroDivisionError -> treated as an *unexpected* crash by the harness.

Note: Using Python's AST to avoid eval() and restrict nodes.
"""

import ast

MAX_LEN = 256
MAX_ABS_RESULT = 10**9

_ALLOWED_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod)
_ALLOWED_UNARY = (ast.UAdd, ast.USub)

def _eval(node):
    if isinstance(node, ast.Expression):
        return _eval(node.body)

    # Numbers (allow ints; floats only as the result of '/')
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):  # int literals in py>=3.8 appear as Constant
            return node.value
        raise ValueError("Only numeric constants allowed")

    # (a op b)
    if isinstance(node, ast.BinOp) and isinstance(node.op, _ALLOWED_BINOPS):
        left = _eval(node.left)
        right = _eval(node.right)

        # Enforce numeric only
        if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
            raise ValueError("Operands must be numeric")

        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            # may raise ZeroDivisionError -> we WANT that to be unexpected
            return left / right
        if isinstance(node.op, ast.FloorDiv):
            return left // right  # ZeroDivisionError possible (unexpected)
        if isinstance(node.op, ast.Mod):
            return left % right   # ZeroDivisionError possible (unexpected)

    # unary +/- a
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, _ALLOWED_UNARY):
        val = _eval(node.operand)
        if not isinstance(val, (int, float)):
            raise ValueError("Operand must be numeric")
        if isinstance(node.op, ast.UAdd):
            return +val
        if isinstance(node.op, ast.USub):
            return -val

    # Parentheses are handled by AST structure automatically
    raise ValueError(f"Unsupported expression element: {type(node).__name__}")

def evaluate(expr: str):
    if not isinstance(expr, str):
        raise ValueError("Expression must be a string")
    expr = expr.strip()
    if not expr:
        raise ValueError("Empty expression")
    if len(expr) > MAX_LEN:
        raise ValueError("Expression too long")

    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as se:
        # expected failure for bad syntax
        raise se

    result = _eval(tree)

    # Enforce magnitude rule (expected failure)
    if isinstance(result, (int, float)) and abs(result) > MAX_ABS_RESULT:
        raise ValueError("Result out of allowed bounds")

    return result
