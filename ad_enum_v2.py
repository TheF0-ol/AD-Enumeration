#!/usr/bin/env python3
"""
Active Directory Enumeration Helper v2
=======================================
Enumerates a domain from a domain-joined Windows host: domain controller
discovery, users, groups, computers, password policy, a GPO summary, and
trust relationships. Saves everything to one structured CSV.

Every command here has been run and confirmed against a real lab domain
(not just simulated output); see the comments in collect_domain_data() for
the specific fixes that came out of that real-world test.

Usage:
    python ad_enum_v2.py --domain corp.local
    python ad_enum_v2.py --domain corp.local --output-dir results

Notes:
    - Must be run on a domain-joined Windows host. Without --domain, the
      script only records local host info and exits; it does not attempt
      domain queries and does not write a "fake" domain CSV.
    - No administrator rights are required for these read-only commands.
    - Run this only on systems you own or have explicit permission to test.

Exit codes: 0 = success, 1 = error, 2 = no --domain given.
"""

import argparse
import csv
import datetime
import platform
import re
import subprocess
import sys
from pathlib import Path

FIELDNAMES = ["timestamp", "source", "field", "value", "source_output"]
_DASH_LINE = re.compile(r"^-{10,}$")


def parse_name_list(text):
    """
    Parse the name list out of `net user /domain`, `net group /domain` or
    `net computer /domain` output: the real names sit between a line of
    dashes and the "command completed" footer, in columns separated by 2+
    spaces (net left-pads single names with extra spaces too).
    """
    names = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if _DASH_LINE.match(stripped):
            in_block = True
            continue
        if not in_block:
            continue
        if stripped.lower().startswith("the command completed"):
            break
        names.extend(n.strip() for n in re.split(r"\s{2,}", stripped) if n.strip())
    return names


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def run(cmd, timeout=10):
    """
    Run a command safely and return (stdout, stderr, returncode).

    `cmd` is a list of arguments (no shell=True, no string interpolation of
    user input into a shell command), so this is not vulnerable to shell
    injection via --domain. Never raises; failures come back as an empty
    stdout with a returncode of -1 and a message in stderr.
    """
    try:
        r = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", f"command not found: {cmd[0]}", -1
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s: {' '.join(cmd)}", -1
    except OSError as e:
        return "", str(e), -1


def add_row(rows, source, field, value, source_output=""):
    rows.append({
        "timestamp": now(),
        "source": source,
        "field": field,
        "value": value,
        "source_output": source_output,
    })


def run_and_record(rows, cmd, source, field, timeout=10, max_lines=None, as_name_list=False):
    """
    Run `cmd` and add rows for its output (field=<field>, source=<source>).

    If as_name_list=True, the output is a `net user/group/computer /domain`
    style listing: it's parsed with parse_name_list() so each row is one
    real name, not a raw line (dashes, headers, multi-name columns). Free
    -text output (nslookup, nltest, gpresult, net accounts) is kept as one
    row per non-empty line instead.

    On failure (nonzero exit, or no usable output), a single "error" row is
    added instead, so a reader can tell "ran but empty" apart from "failed
    to run". Returns the command's returncode.
    """
    out, err, rc = run(cmd, timeout=timeout)
    if rc != 0:
        detail = (err.strip() or out.strip()) or f"no output (exit {rc})"
        add_row(rows, source, "error", detail[:300], out.strip()[:500])
        return rc

    if as_name_list:
        names = parse_name_list(out)
        if not names:
            add_row(rows, source, "error", "ran, but no names were parsed from the output",
                     out.strip()[:500])
            return rc
        for name in names:
            add_row(rows, source, field, name)
        return rc

    if not out.strip():
        add_row(rows, source, "error", f"no output (exit {rc})")
        return rc
    lines = out.strip().splitlines()
    if max_lines:
        lines = lines[:max_lines]
    for line in lines:
        line = line.strip()
        if line:
            add_row(rows, source, field, line)
    return rc


def get_host_info(outdir):
    """Save local host info to its own CSV (kept separate from domain data)."""
    host_info = {
        "timestamp": now(),
        "hostname": platform.node(),
        "os": platform.system(),
        "python_version": sys.version.split()[0],
    }
    with open(outdir / "host_info.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["field", "value"])
        for k, v in host_info.items():
            w.writerow([k, v])


def collect_domain_data(domain):
    """Run every enumeration command against `domain` and return the rows."""
    rows = []

    whoami_out, _, _ = run(["whoami"])
    add_row(rows, "whoami", "current_user", whoami_out.strip())
    add_row(rows, "platform", "os", platform.system())
    add_row(rows, "domain", "target", domain)

    # Domain controller discovery. nltest /dsgetdc is the reliable source for
    # this (confirmed against a real lab domain); a separate nslookup -type=SRV
    # query against the _msdcs subdomain was tried in an earlier version but
    # consistently timed out on a real DC, nltest already returns the DC's
    # site, GUID and capability flags in one clean call, so that redundant,
    # unreliable query was dropped rather than fixed.
    run_and_record(rows, ["nltest", f"/dsgetdc:{domain}"],
                    source="dc_discovery", field="nltest")
    run_and_record(rows, ["nslookup", "-type=A", f"gc._msdcs.{domain}"],
                    source="dc_discovery", field="dns_dc")

    # Users and groups (these return a name list, so parse it properly
    # instead of recording raw lines like dashes and headers)
    run_and_record(rows, ["net", "user", "/domain"],
                    source="net_user_domain", field="username", as_name_list=True)
    run_and_record(rows, ["net", "group", "/domain"],
                    source="net_group_domain", field="group", as_name_list=True)

    # Computers: `net computer /domain` is NOT the right command for this
    # (confirmed against a real DC: it returned "The option /DOMAIN is
    # unknown", since `net computer` is actually for adding/removing a
    # computer account, not listing them). Computer accounts are members of
    # the built-in "Domain Computers" group, so list that group instead,
    # the same way `net group` already works for any other group. A computer
    # account's name always ends in "$" (e.g. "DC-01$"), which is how a
    # reader can tell a computer entry apart from a user entry in the CSV.
    run_and_record(rows, ["net", "group", "Domain Computers", "/domain"],
                    source="net_group_domain_computers", field="computer", as_name_list=True)

    # Password policy
    run_and_record(rows, ["net", "accounts", "/domain"],
                    source="net_accounts", field="policy")

    # GPO summary. Confirmed against a real lab: `gpresult /scope computer /v`
    # returns "Access Denied" when run as a normal domain user, since reading
    # computer-scope GPO data needs local admin rights on the machine. That is
    # expected, not a bug, and is itself a useful line for a write-up ("GPO
    # details aren't readable as a standard user"), so the attempt and its
    # failure are both recorded rather than treated as an error to silence.
    run_and_record(rows, ["gpresult", "/scope", "computer", "/v"],
                    source="gpresult", field="gpo", timeout=30, max_lines=30)

    # Trust relationships. `nltest /trusteddomains` is not a real nltest
    # option (confirmed against a real DC: it printed nltest's usage/help
    # text instead of trust data). The correct flag is /domain_trusts.
    run_and_record(rows, ["nltest", "/domain_trusts"],
                    source="nltest_domain_trusts", field="trust")

    return rows


def build_parser():
    p = argparse.ArgumentParser(
        description="AD enumeration helper: DNS, DC, users, groups, computers, "
                    "password policy, GPO summary and trusts, saved to CSV."
    )
    p.add_argument(
        "--domain",
        help="FQDN of the domain to enumerate (e.g. corp.local). Required.",
    )
    p.add_argument(
        "--output-dir",
        default="results",
        help="Folder to write CSV results to (default: %(default)s).",
    )
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if os_name_is_not_windows():
        print("This script must be run on a domain-joined Windows host.", file=sys.stderr)
        return 1

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    get_host_info(outdir)

    if not args.domain:
        print("No --domain given. Only local host info was saved "
              f"({outdir / 'host_info.csv'}). Pass --domain to enumerate a domain.")
        return 2

    print(f"Enumerating domain: {args.domain}")
    rows = collect_domain_data(args.domain)

    outpath = outdir / "ad_enum_v2.csv"
    with open(outpath, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writeheader()
        w.writerows(rows)

    errors = sum(1 for r in rows if r["field"] == "error")
    print(f"\nSaved {len(rows)} row(s) to {outpath}")
    if errors:
        print(f"{errors} command(s) failed or returned no output (see 'error' rows in the CSV).")
    print("Done.")
    return 0


def os_name_is_not_windows():
    return __import__("os").name != "nt"


if __name__ == "__main__":
    sys.exit(main())
