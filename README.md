# Emmanuel Gbenga Medelu 
### Student number: 23754782
# Fuzzing CI Tool Guide

This project is a **Python-based fuzz testing framework** with a CI/CD pipeline integrated into GitHub Actions. It demonstrates how to fuzz multiple targets (JSON, YAML, Markdown, a custom Edge-case function, and a Calculator mini-app), classify expected vs. unexpected failures, and collect artifacts.

---

## 📂 Project Structure

```
fuzzing-ci-tool/
├── fuzz_tool/
│   ├── fuzzer.py               # Fuzzer harness (CLI, JSON reporting, artifacts, pretty output)
│   ├── targets/
│   │   ├── json_parser.py      # JSON parsing target
│   │   ├── yaml_parser.py      # YAML parsing target
│   │   ├── markdown_parser.py  # Markdown parsing target
│   │   ├── edge_case.py        # Edge-case buggy logic (crashes on purpose)
│   │   └── app_calc.py         # Mini calculator app (simulates real software)
│   └── corpus/                 # Seed corpus files (valid and crashing inputs)
├── run_fuzzer.py               # Entry point for running fuzzing
├── requirements.txt            # Dependencies (atheris, PyYAML, markdown, rich, tabulate)
├── README.md                   # Developer documentation (this file)
└── .github/workflows/fuzz.yml  # GitHub Actions workflow for CI fuzzing
```

---

## 🚀 Setup & Installation

### Requirements
- Python **3.10** (Atheris only supports 3.7–3.10).
- `pip` updated to the latest version.

### Steps
```bash
# Clone repo
git clone https://github.com/<your-username>/fuzzing-ci-tool.git
cd fuzzing-ci-tool

# Create virtual environment
python3.10 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 🧪 Running Locally

### Run the fuzzer
Each target can be fuzzed separately. Example:

```bash
# JSON target (60s, using seed corpus)
python run_fuzzer.py --target json --time_budget 60 fuzz_tool/corpus

# YAML target
python run_fuzzer.py --target yaml --time_budget 60 fuzz_tool/corpus

# Markdown target
python run_fuzzer.py --target markdown --time_budget 60 fuzz_tool/corpus

# Edge-case target (intentionally buggy)
python run_fuzzer.py --target edge --time_budget 60 fuzz_tool/corpus

# Calculator mini-app (realistic demo)
python run_fuzzer.py --target calc --time_budget 60 fuzz_tool/corpus
```

### Options
- `--time_budget <seconds>`: Max run time.
- `--max_len <bytes>`: Max input size (default 4096).
- `--seed <int>`: Deterministic seed for reproducibility.
- `--artifacts-dir <dir>`: Where to store crashes & summary (default `reports/`).
- `--continue_on_crash`: Record crashes but keep fuzzing (good for demos).
- `corpus`: Optional initial corpus directories.

---

## 📊 Outputs

When fuzzing finishes:
- `reports/<target>/run_summary.json` → summary (inputs processed, handled vs. unexpected exceptions, duration, crashes list).
- `reports/<target>/crash_<sha1>.input` → exact crashing input bytes.
- `reports/<target>/crash_<sha1>.json` → crash metadata (exception type, message, traceback, input preview, seed).

Additionally, a **pretty console table** is printed with Rich/Tabulate, and a Markdown summary is exported to GitHub Actions logs.

---

## 🔄 CI/CD Pipeline

### Location
`.github/workflows/fuzz.yml`

### Behavior
- Runs automatically on:
  - Push to `master`
  - Pull requests into `master`
  - Nightly schedule at 01:30 UTC
- Matrix runs for all targets (json, yaml, markdown, edge, calc).
- Ensures **reports/** always exist and uploads artifacts per target.
- Adds Markdown summary (`GITHUB_STEP_SUMMARY`) for readability.
- Optional `fuzz-gate` job can fail PRs if unexpected crashes > 0.

### Example job in CI logs

```
## Fuzzing Run Summary — calc

| Metric               | Value   |
|----------------------|---------|
| Target               | calc    |
| Total Inputs         | 153242  |
| Handled Exceptions   | 310     |
| Unexpected (Crashes) | 1       |
| Duration (s)         | 30.002  |
| Artifacts dir        | reports/calc |
```

Artifacts are downloadable from the Actions run page.

---

## 🛠️ Adding a New Target

1. Create a new file under `fuzz_tool/targets/` (e.g., `my_parser.py`) with a `process(data: str)` function.
2. Import and add it in `fuzz_tool/fuzzer.py` under `TARGET_FUNCS` and `EXPECTED_EXCEPTIONS`.
3. Add seed corpus files under `fuzz_tool/corpus/`.
4. Update `.github/workflows/fuzz.yml` to include your target.

---

## 🧾 Example Commands

```bash
# Force a simulated crash quickly (calc target)
echo "10/0" > fuzz_tool/corpus/divzero.txt
python run_fuzzer.py --target calc --time_budget 30 fuzz_tool/corpus

# Reproduce a crash from artifacts
python -c "from fuzz_tool.targets import app_calc; print(app_calc.evaluate('10/0'))"
```

---

## ✅ Developer Notes

- Always use Python 3.10 for compatibility with Atheris.
- For debugging, add `--continue_on_crash` so you see the summary table even after crashes.
- Each run writes a summary file, ensuring CI never warns about missing artifacts.
- Use seed corpus files to guide fuzzing (valid + invalid samples).

---

## 📌 Summary

This project gives you a **full fuzzing CI/CD demo**:
- Targets multiple parsers + a realistic mini-app.
- Clear separation of **expected vs. unexpected** exceptions.
- Pretty console + CI/CD Markdown reports.
- Artifact storage for reproducible crash analysis.

You can extend this project to any Python function or library you want to test!
