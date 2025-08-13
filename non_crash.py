import atheris
import sys
import os
import json

from fuzz_tool.targets import json_parser

def test_one_input(data):
    fdp = atheris.FuzzedDataProvider(data)
    input_str = fdp.ConsumeUnicodeNoSurrogates(100)

    try:
        # Attempt to parse the input
        json_parser.parse_json(input_str)
    except json.JSONDecodeError:
        pass
    except Exception as e:
        # Optional: log failures to console (or to a file if needed)
        print(f"[Handled] {type(e).__name__}: {e} on input {repr(input_str)}")
        pass  # Do not crash or write report

def main():
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
