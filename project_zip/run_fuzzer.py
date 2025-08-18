# from fuzz_tool import fuzzer
#
# if __name__ == "__main__":
#     fuzzer.main()


from fuzz_tool.fuzzer import main

if __name__ == "__main__":
    raise SystemExit(main() or 0)
