#!/usr/bin/env python3
"""PatchPilot prototype: SARIF finding -> Claude -> suggested unified diff.

Experimental. Suggests a patch only; it never edits your files. Before showing
a diff it checks that the diff's context matches the real file text. It does
NOT run your tests or prove the fix is correct. Review every patch yourself.
"""
import argparse
import json
import os
import re
import sys
from urllib.parse import unquote

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_FILE_BYTES = 200_000
FENCE = re.compile(r"```(?:diff|patch)?[ \t]*\n(.*?)```", re.S)

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
hunks) against the exact file contents above, and nothing else."""


class PatchPilotError(Exception):
    """A problem we can explain to the user in one line."""


def load_findings(sarif_path):
    try:
        with open(sarif_path, encoding="utf-8") as f:
            sarif = json.load(f)
    except FileNotFoundError:
        raise PatchPilotError(f"SARIF file not found: {sarif_path}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise PatchPilotError(f"{sarif_path} is not valid JSON (is the file empty?)")
    if not isinstance(sarif, dict):
        raise PatchPilotError("SARIF root must be a JSON object")
    findings = []
    for run in sarif.get("runs") or []:
        for res in (run or {}).get("results") or []:
            try:
                phys = res["locations"][0]["physicalLocation"]
                uri = phys["artifactLocation"]["uri"]
            except (KeyError, IndexError, TypeError):
                continue  # finding without a file location
            if uri.startswith("file://"):
                uri = uri[7:]
            region = phys.get("region") or {}
            findings.append({
                "rule": res.get("ruleId", "unknown"),
                "message": (res.get("message") or {}).get("text", ""),
                "path": unquote(uri),
                "line": region.get("startLine", 1),
            })
    return findings


def resolve_path(root, rel):
    """Resolve rel inside root; refuse anything that escapes root."""
    root_abs = os.path.realpath(root)
    full = os.path.realpath(os.path.join(root_abs, rel))
    try:
        inside = os.path.commonpath([root_abs, full]) == root_abs
    except ValueError:
        inside = False
    if not inside:
        raise PatchPilotError(f"refusing path outside --root: {rel}")
    return full


def read_source(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            raise PatchPilotError(f"{path} is larger than {MAX_FILE_BYTES} bytes; skipped")
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise PatchPilotError(f"cannot read {path}: {e.strerror or e}")
    if b"\0" in data:
        raise PatchPilotError(f"{path} looks binary; skipped")
    return data.decode("utf-8", errors="replace")


def build_prompt(finding, source):
    return PROMPT.format(code=source, **finding)


def extract_diff(text):
    """Pull a unified diff out of a model reply, or return None."""
    m = FENCE.search(text)
    lines = (m.group(1) if m else text).splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith("--- ")), None)
    if start is None:
        return None
    diff = "\n".join(lines[start:]).strip("\n") + "\n"
    if not re.search(r"^\+\+\+ ", diff, re.M) or not re.search(r"^@@ ", diff, re.M):
        return None
    return diff


def diff_problems(diff, source):
    """Check each hunk's old lines really appear in the file. [] means OK."""
    src = [l.rstrip() for l in source.splitlines()]
    hunks, cur = [], None
    for line in diff.splitlines():
        if line.startswith("@@"):
            cur = []
            hunks.append(cur)
        elif cur is not None and not line.startswith("\\"):
            cur.append(line)
    if not hunks:
        return ["no hunks found"]
    problems = []
    for n, hunk in enumerate(hunks, 1):
        old = []
        for l in hunk:
            if l[:1] in ("-", " "):
                old.append(l[1:].rstrip())
            elif l == "":
                old.append("")
        if old and not any(src[i:i + len(old)] == old
                           for i in range(len(src) - len(old) + 1)):
            problems.append(f"hunk {n} does not match the file text")
    return problems


def make_client():
    try:
        import anthropic
    except ImportError:
        raise PatchPilotError("Install the SDK first: py -m pip install anthropic")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise PatchPilotError("ANTHROPIC_API_KEY is not set (see README).")
    return anthropic.Anthropic(max_retries=3, timeout=90.0)


def ask_claude(client, model, messages):
    import anthropic
    try:
        msg = client.messages.create(model=model, max_tokens=2000, messages=messages)
    except anthropic.AuthenticationError:
        raise PatchPilotError("API key rejected. Check ANTHROPIC_API_KEY.")
    except anthropic.RateLimitError:
        raise PatchPilotError("Rate limited or out of quota. Wait, or check your balance.")
    except anthropic.APIConnectionError:
        raise PatchPilotError("Could not reach the Anthropic API. Check your connection.")
    except anthropic.APIStatusError as e:
        raise PatchPilotError(f"API error {getattr(e, 'status_code', '?')}: {e}")
    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


def fix_finding(client, model, finding, root, attempts):
    source = read_source(resolve_path(root, finding["path"]))
    messages = [{"role": "user", "content": build_prompt(finding, source)}]
    problems = []
    for _ in range(attempts):
        text = ask_claude(client, model, messages)
        diff = extract_diff(text)
        problems = (["the reply contained no unified diff"] if diff is None
                    else diff_problems(diff, source))
        if not problems:
            return diff
        messages += [
            {"role": "assistant", "content": text or "(empty reply)"},
            {"role": "user", "content": "That diff was rejected: " + "; ".join(problems)
             + ". Reply with ONLY a corrected unified diff against the exact file above."},
        ]
    raise PatchPilotError("no valid diff after %d attempt(s): %s" % (attempts, "; ".join(problems)))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sarif", required=True, help="Path to a SARIF file")
    ap.add_argument("--root", default=".", help="Folder the SARIF paths are relative to")
    ap.add_argument("--dry-run", action="store_true", help="Print prompts; do not call the API")
    ap.add_argument("--model", default=os.environ.get("PATCHPILOT_MODEL", DEFAULT_MODEL))
    ap.add_argument("--max-findings", type=int, default=5, help="Cap API calls (default 5)")
    ap.add_argument("--attempts", type=int, default=2, help="Tries per finding (default 2)")
    ap.add_argument("--out", help="Folder to save each diff as a .diff file")
    args = ap.parse_args(argv)

    try:
        findings = load_findings(args.sarif)
        if not findings:
            raise PatchPilotError("no findings with file locations in this SARIF file")
        if len(findings) > args.max_findings:
            print(f"Note: {len(findings)} findings found; processing the first {args.max_findings}.")
            findings = findings[:args.max_findings]
        client = None if args.dry_run else make_client()
    except PatchPilotError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    failures = 0
    for i, f in enumerate(findings, 1):
        print(f"=== Finding {i}/{len(findings)}: {f['rule']} in {f['path']}:{f['line']} ===")
        try:
            if args.dry_run:
                source = read_source(resolve_path(args.root, f["path"]))
                print(build_prompt(f, source))
                continue
            diff = fix_finding(client, args.model, f, args.root, max(1, args.attempts))
        except PatchPilotError as e:
            failures += 1
            print(f"Skipped: {e}", file=sys.stderr)
            continue
        print(diff)
        print("Checked: diff context matches the file. Tests were NOT run; review before applying.")
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            name = os.path.join(args.out, f"finding{i}.diff")
            with open(name, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(diff)
            print(f"Saved {name}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
