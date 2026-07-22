"""Command-line interface for PyPIGuard, so the model can be used as a
standalone reusable tool (in a terminal, CI job, or pre-commit hook)
instead of only through the Flask web UI. Same detection core as the
web app (pypiguard.core), so results are identical to the web version.

Usage:
    pypiguard scan <package_name> [<package_name> ...]
    pypiguard scan-file <archive_path>
    pypiguard scan-requirements <requirements.txt> [--fail-on-malicious]

Exit codes (for CI use):
    0  all scanned targets benign (or --fail-on-malicious not set)
    1  at least one target flagged malicious and --fail-on-malicious set
    2  usage / lookup error
"""
import argparse
import json
import re
import sys

from . import core


def _print_verdict(result, as_json):
    if as_json:
        print(json.dumps(result, indent=2, default=str))
        return
    name = result.get("package_name", "?")
    verdict = result.get("verdict", "?")
    conf = result.get("confidence", "?")
    source = result.get("source", "?")
    ood = result.get("out_of_distribution")
    flag = " [OUT-OF-DISTRIBUTION: interpret with caution]" if ood else ""
    print(f"{name}: {verdict.upper()} (confidence {conf}%, source={source}){flag}")
    for ind in result.get("flagged_indicators", []) or []:
        print(f"    - {ind['label']}")


def cmd_scan(args):
    exit_code = 0
    for pkg in args.package_name:
        try:
            result = core.scan_package_name(pkg)
        except ValueError as e:
            print(f"{pkg}: ERROR - {e}", file=sys.stderr)
            exit_code = max(exit_code, 2)
            continue
        _print_verdict(result, args.json)
        if result.get("verdict") == "malicious" and args.fail_on_malicious:
            exit_code = 1
    return exit_code


def cmd_scan_file(args):
    try:
        result = core.scan_local_archive(args.archive_path, package_name=args.name)
    except Exception as e:
        print(f"ERROR scanning {args.archive_path}: {e}", file=sys.stderr)
        return 2
    _print_verdict(result, args.json)
    if result.get("verdict") == "malicious" and args.fail_on_malicious:
        return 1
    return 0


_REQ_LINE_RE = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)')


def _parse_requirements(path):
    names = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = _REQ_LINE_RE.match(line)
            if m:
                names.append(m.group(1))
    return names


def cmd_scan_requirements(args):
    names = _parse_requirements(args.requirements_file)
    if not names:
        print(f"No package names parsed from {args.requirements_file}", file=sys.stderr)
        return 2
    exit_code = 0
    results = []
    for pkg in names:
        try:
            result = core.scan_package_name(pkg)
        except ValueError as e:
            print(f"{pkg}: ERROR - {e}", file=sys.stderr)
            exit_code = max(exit_code, 2)
            continue
        results.append(result)
        _print_verdict(result, args.json)
        if result.get("verdict") == "malicious":
            exit_code = 1 if args.fail_on_malicious else exit_code

    n_mal = sum(1 for r in results if r.get("verdict") == "malicious")
    if not args.json:
        print(f"\n{len(results)} scanned, {n_mal} flagged malicious.")
    return exit_code


def main(argv=None):
    parser = argparse.ArgumentParser(prog="pypiguard", description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable text.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan one or more live PyPI package names.")
    p_scan.add_argument("package_name", nargs="+")
    p_scan.add_argument("--fail-on-malicious", action="store_true",
                         help="Exit 1 if any scanned package is flagged malicious (for CI).")
    p_scan.set_defaults(func=cmd_scan)

    p_file = sub.add_parser("scan-file", help="Scan a local .tar.gz/.zip/.whl archive.")
    p_file.add_argument("archive_path")
    p_file.add_argument("--name", default=None, help="Display name (default: filename).")
    p_file.add_argument("--fail-on-malicious", action="store_true")
    p_file.set_defaults(func=cmd_scan_file)

    p_req = sub.add_parser("scan-requirements", help="Scan every package named in a requirements.txt.")
    p_req.add_argument("requirements_file")
    p_req.add_argument("--fail-on-malicious", action="store_true",
                        help="Exit 1 if any dependency is flagged malicious (for CI gating).")
    p_req.set_defaults(func=cmd_scan_requirements)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
