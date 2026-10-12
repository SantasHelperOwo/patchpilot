PatchPilot

An early-stage experiment: take a static-analysis finding (SARIF), ask Claude for a minimal fix, and review the result as a unified diff.

Status: experimental prototype. Not production software. Website: https://patchpilot.me

What exists today
Website and in-browser demo replay (index.html). The demo is an illustration, not a real run.
A small command-line prototype (src/patchpilot.py) that reads a SARIF file, collects the flagged code, and asks Claude for a suggested diff.
What does not exist yet
Running a project's tests against the patch
Opening pull requests or a GitHub Action
Sandboxed verification
Benchmarks or accuracy numbers. There are none.

The prototype only suggests a diff. It does not apply it, verify it, or guarantee it is correct. Always review generated code yourself.

Try it
bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key_here    # never commit your key

# See the prompt without calling the API (no key needed):
python src/patchpilot.py --sarif examples/sample.sarif --root examples --dry-run

# Ask Claude for a suggested diff:
python src/patchpilot.py --sarif examples/sample.sarif --root examples

Set PATCHPILOT_MODEL to choose a Claude model (default: claude-sonnet-5-5).

Roadmap
Months 1-2: Python CLI that accepts Semgrep SARIF and returns unified diffs from Claude.
Months 3-4: Local Docker verification that runs a project's existing tests against each diff.
Months 5-6: GitHub Action that opens draft pull requests on open-source test repositories.
Author

Atip Shrestha, BSc (Hons) Ethical Hacking and Cybersecurity student, Softwarica College, Nepal. Solo, self-funded project started October 2026.

Contact: contact@patchpilot.me
