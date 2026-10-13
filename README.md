# PatchPilot

An early-stage experiment: take a static-analysis finding (SARIF), ask Claude for a minimal fix, and review the result as a unified diff.

**Status: experimental prototype. Not production software.** Website: https://patchpilot.me

## What exists today

- Website and in-browser demo replay (`index.html`). The demo is an illustration, not a real run.
- A small command-line prototype (`src/patchpilot.py`) that reads a SARIF file, collects the flagged code, and asks Claude for a suggested diff.

## What does not exist yet

- Running a project's tests against the patch
- Opening pull requests or a GitHub Action
- Sandboxed verification
- Benchmarks or accuracy numbers. There are none.

The prototype only *suggests* a diff. It does not apply it, verify it, or guarantee it is correct. Always review generated code yourself.

## Try it

**Windows (Command Prompt):**
```
py -m pip install -r requirements.txt
set ANTHROPIC_API_KEY=your_key_here
py src\patchpilot.py --sarif examples\sample.sarif --root examples --dry-run
py src\patchpilot.py --sarif examples\sample.sarif --root examples
```

**Mac / Linux:**
```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key_here    # never commit your key
python src/patchpilot.py --sarif examples/sample.sarif --root examples --dry-run
python src/patchpilot.py --sarif examples/sample.sarif --root examples
```

`--dry-run` prints the prompt and needs no API key. Useful options: `--out diffs` saves each diff to a file, `--max-findings` caps API calls (default 5), `--attempts` sets retries (default 2). Set `PATCHPILOT_MODEL` to choose a Claude model (default: `claude-sonnet-5-5`).

Before showing a diff, the tool checks that the diff's context matches the real file and retries once if not. It does not run your tests.

## Tests

```
py -m unittest discover -s tests -v
```

The tests run offline with a simulated API response. The live Claude call itself has not been benchmarked.

## Roadmap

1. **Months 1-2:** Python CLI that accepts Semgrep SARIF and returns unified diffs from Claude.
2. **Months 3-4:** Local Docker verification that runs a project's existing tests against each diff.
3. **Months 5-6:** GitHub Action that opens draft pull requests on open-source test repositories.

## Author

Atip Shrestha, BSc (Hons) Ethical Hacking and Cybersecurity student, Softwarica College, Nepal. Solo, self-funded project started October 2026.

Contact: contact@patchpilot.me
