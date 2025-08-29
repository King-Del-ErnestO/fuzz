import re

def process(data: str):
    """
    Deliberately quirky target to simulate real application crashes.

    Triggers:
      - Starts with 'CRASH!' -> ZeroDivisionError (simulated crash)
      - Contains NUL -> ValueError
      - Length > 3000 -> BufferError (boundary issue)
      - CSV of ints whose sum == 1337 -> RuntimeError
    """
    # if data.startswith("CRASH!"):
    #     return 1 / 0  # ZeroDivisionError

    if "\x00" in data:
        raise ValueError("NUL byte not allowed")

    if len(data) > 3000:
        raise BufferError("Input too large")

    # CSV integers pattern
    if re.fullmatch(r"(?:\s*-?\d+\s*,)*\s*-?\d+\s*", data or ""):
        nums = [int(x) for x in data.split(",") if x.strip()]
        if sum(nums) == 1337:
            raise RuntimeError("Simulated crash: magic sum 1337")
        return sum(nums)

    # Mild regex touch to simulate parsing effort
    re.search(r"[A-Za-z0-9_\- ]{0,256}", data or "")
    return None
