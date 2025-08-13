import atheris
import sys
import os

from fuzz_tool.targets import json_parser


os.makedirs("reports", exist_ok=True)


def test_one_input(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        input_str = fdp.ConsumeUnicodeNoSurrogates(100)
        print(f"Fuzzing input: {repr(input_str)}")
        json_parser.parse_json(input_str)

    except Exception as e:
        with open(f"reports/crash_{hash(input_str)}.txt", "w") as f:
            f.write(input_str)
        print(f"Exception: {type(e).__name__}: {e}")
        raise RuntimeError(f"Crash with input: {repr(input_str)} saved to reports/crash_{hash(input_str)}.txt") from e


# We just want to observe crashes

def main():
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
