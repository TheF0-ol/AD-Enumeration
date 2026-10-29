#!/usr/bin/env python3
"""
AD Enumeration Helper

Runs read-only domain enumeration commands from a domain-joined Windows host
and saves the parsed results to CSV, one row per account / group member.

Usage:
    python ad_enum.py
    python ad_enum.py --domain corp.local
    python ad_enum.py --groups "Domain Admins,Domain Users" --output-dir results

Notes:
    - No administrator rights are needed. "net user /domain" and
      "net group /domain" run as a normal domain user.
    - Run this only in environments you own or are authorized to test.
    - On a machine that is not domain-joined (WORKGROUP), the script says so
      and exits without writing any file.
    - Output parsing assumes English-language Windows.

Exit codes: 0 = success, 1 = error, 2 = host is not domain-joined.
"""

import argparse
import csv
import getpass
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

DEFAULT_GROUPS = "Domain Admins,Enterprise Admins,Domain Controllers,Domain Users"
CSV_FIELDS = ["timestamp", "domain", "source", "object_type", "group", "name"]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_DOMAIN = 2

_DASH_LINE = re.compile(r"^-{10,}$")


def run_cmd(cmd, timeout=30):
    """Run a command and return (stdout, stderr, returncode). Never raises."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", f"command not found: {cmd[0]}", -1
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s: {' '.join(cmd)}", -1
    except OSError as e:
        return "", str(e), -1


def get_domain_context():
    """Return (is_domain_joined, domain_name) for this host."""
    ps_cmd = (
        "$c = Get-CimInstance Win32_ComputerSystem; "
        "$c.PartOfDomain.ToString() + '|' + $c.Domain"
    )
    out, _err, rc = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd])
    if rc == 0 and "|" in out:
        part_of_domain, domain = out.strip().split("|", 1)
        return part_of_domain.strip().lower() == "true", domain.strip()

    # Fallback if PowerShell/CIM is unavailable: a domain logon sets USERDNSDOMAIN.
    dns_domain = os.environ.get("USERDNSDOMAIN", "")
    return bool(dns_domain), dns_domain


def domain_matches(requested, actual):
    """True if the requested domain is the machine's domain (FQDN or short name)."""
    a, b = requested.strip().lower(), actual.strip().lower()
    return a == b or a.split(".")[0] == b.split(".")[0]


def net_user_domain():
    return run_cmd(["net", "user", "/domain"])


def net_group(group):
    return run_cmd(["net", "group", group, "/domain"])


def parse_names(text):
    """
    Parse the name list from `net user /domain` or the Members section of
    `net group "<group>" /domain`.

    Names sit in columns after a line of dashes and end at
    "The command completed successfully." Names may contain single spaces,
    so columns are split on runs of 2+ spaces.
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
        # Attribute lines (e.g. "  Comment = Administrator") are not names.
        if "=" in stripped:
            continue
        names.extend(n.strip() for n in re.split(r"\s{2,}", stripped) if n.strip())
    return names


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)


def build_parser():
    p = argparse.ArgumentParser(description="Read-only AD enumeration helper.")
    p.add_argument(
        "--domain",
        help="Expected domain (e.g. corp.local). The script exits if this host "
             "belongs to a different domain. Defaults to the host's own domain.",
    )
    p.add_argument(
        "--groups",
        default=DEFAULT_GROUPS,
        help="Comma-separated domain groups to list (default: %(default)s)",
    )
    p.add_argument(
        "--output-dir",
        default=".",
        help="Directory for the CSV file (default: current directory)",
    )
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if os.name != "nt":
        print("This script must be run on a domain-joined Windows host.", file=sys.stderr)
        return EXIT_ERROR

    groups = [g.strip() for g in args.groups.split(",") if g.strip()]

    who_out, _, _ = run_cmd(["whoami"])
    print(f"Running as: {getpass.getuser()} ({who_out.strip() or 'whoami failed'})"
          f"  |  Host: {os.environ.get('COMPUTERNAME', 'unknown')}")

    joined, machine_domain = get_domain_context()
    if not joined:
        print("\nThis host is not domain-joined (WORKGROUP), so domain enumeration "
              "would fail with error 1355. Nothing was run and no file was written.")
        return EXIT_NOT_DOMAIN

    if args.domain and not domain_matches(args.domain, machine_domain):
        print(f"\nRequested domain '{args.domain}' does not match this host's domain "
              f"'{machine_domain}'. Nothing was run.", file=sys.stderr)
        return EXIT_ERROR

    domain = machine_domain
    print(f"Domain: {domain}")

    stamp = datetime.now()
    timestamp = stamp.isoformat(timespec="seconds")
    rows = []

    # Users
    print("\nEnumerating domain users (net user /domain)...")
    out, err, rc = net_user_domain()
    if rc != 0:
        print(f"Error (exit {rc}): {(err.strip() or out.strip()) or 'no details'}",
              file=sys.stderr)
        return EXIT_ERROR
    users = parse_names(out)
    print(f"  Found {len(users)} user account(s).")
    for name in users:
        rows.append({"timestamp": timestamp, "domain": domain,
                     "source": "net user /domain", "object_type": "user",
                     "group": "", "name": name})

    # Groups
    failed_groups = []
    for grp in groups:
        print(f"\n{grp} (net group /domain)...")
        g_out, g_err, g_rc = net_group(grp)
        if g_rc != 0:
            detail = (g_err.strip() or g_out.strip()) or "no details"
            print(f"  Skipped: {detail}")
            failed_groups.append(grp)
            continue
        members = parse_names(g_out)
        print(f"  {len(members)} member(s).")
        for name in members:
            rows.append({"timestamp": timestamp, "domain": domain,
                         "source": f'net group "{grp}" /domain',
                         "object_type": "group_member", "group": grp, "name": name})

    out_dir = Path(args.output_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"ad_enum_{stamp.strftime('%Y%m%d_%H%M%S')}.csv"
        write_csv(out_path, rows)
    except OSError as e:
        print(f"Could not write CSV: {e}", file=sys.stderr)
        return EXIT_ERROR

    print(f"\nSaved {len(rows)} row(s) to {out_path}")
    if failed_groups:
        print(f"Groups that could not be read: {', '.join(failed_groups)}")
    print("Done.")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
