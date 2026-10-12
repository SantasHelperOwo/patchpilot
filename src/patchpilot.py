#!/usr/bin/env python3
"""PatchPilot prototype: SARIF finding -> Claude -> suggested unified diff.

Experimental. Suggests a patch only; does not apply or verify it.
"""
import argparse
import json
import os
import sys

DEFAULT_MODEL = "claude-sonnet-5-5"

PROMPT = """You are helping fix a security finding found by a static analysis tool.

Rule: {rule}
Finding: {message}
File: {path} (flagged at line {line})

Full file contents:
```
{code}
```

Write the smallest change that fixes this vulnerability without altering
unrelated behavior. Respond with ONLY a unified diff (---/+++ headers and @@
hunks) and nothing else."""


def load_findings(sarif_path):
    with open(sarif_path, encoding="utf-8") as f:
        sarif = json.load(f)
    findings = []
    for run in sarif.get("runs", []):
        for res in run.get("results", []):
            locs = res.get("locations") or []
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri")
            if not uri:
                continue
            findings.append({
                "rule": res.get("ruleId", "unknown"),
                "message": res.get("message", {}).get("text", ""),
                "path": uri,
                "line": phys.get("region", {}).get("startLine", 1),
            })
    return findings


def build_prompt(finding, root):
    full = os.path.join(root, finding["path"])
    try:
        with open(full, encoding="utf-8") as f:
            code = f.read()
    except OSError as e:
        raise SystemExit(f"Cannot read {full}: {e}")
    return PROMPT.format(code=code, **finding)


def ask_claude(prompt, model):
    try:
        import anthropic
    except ImportError:
        raise SystemExit("Install the SDK first: pip install anthropic")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("Set ANTHROPIC_API_KEY in your environment.")
    client = anthropic.Anthropic()
    msg = client.messages.create(
        model=model,
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(b.text for b in msg.content if b.type == "text")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sarif", required=True, help="Path to a SARIF file")
    ap.add_argument("--root", default=".", help="Folder the SARIF paths are relative to")
    ap.add_argument("--dry-run", action="store_true", help="Print the prompt, do not call the API")
    ap.add_argument("--model", default=os.environ.get("PATCHPILOT_MODEL", DEFAULT_MODEL))
    args = ap.parse_args()

    findings = load_findings(args.sarif)
    if not findings:
        sys.exit("No findings with file locations in this SARIF file.")

    for i, f in enumerate(findings, 1):
        print(f"=== Finding {i}/{len(findings)}: {f['rule']} in {f['path']}:{f['line']} ===")
        prompt = build_prompt(f, args.root)
        if args.dry_run:
            print(prompt)
        else:
            print(ask_claude(prompt, args.model))
        print()


if __name__ == "__main__":
    main()
