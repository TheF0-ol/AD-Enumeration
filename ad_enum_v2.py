#!/usr/bin/env python3
"""
Active Directory Enumeration Helper v2
=======================================
Lightweight AD enumeration for learning + internship reporting.

Covers: DNS, domain controllers, users, groups, computers, password policy,
        GPO list, and trust relationships. Outputs structured CSV + readable text.

Usage:
    python ad_enum.py [--domain CORP.LOCAL] [--output-dir AD]

Notes:
    - On a domain-joined machine with the right tools, --domain returns real data.
    - On a WORKGROUP machine (most intern labs), --domain will fail with error 1355.
      Document that as a valid finding: target not domain-joined.

Scope: Learning utility. Not a security scanner. Only use against hosts you own
or have explicit permission to test.
"""

import argparse
import csv
import datetime
import platform
import subprocess
import sys
from pathlib import Path

def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

def run(cmd, timeout=10):
    """Run a shell command, return (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except Exception as e:
        return "", str(e), -1

def save_csv(path, rows, fieldnames):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow(row)

def get_host_info(outdir):
    """Save host info to CSV."""
    host_info = {
        "timestamp": now(),
        "hostname": platform.node(),
        "os": platform.system(),
        "python_version": sys.version.split()[0],
        "command_line": " ".join(sys.argv),
    }
    outdir.joinpath("host_info.csv").write_text(
        "\n".join(f"{k},{v}" for k, v in host_info.items()),
        encoding="utf-8"
    )

def collect_data(domain):
    """Run enumeration commands and collect results."""
    all_rows = []

    # Local context
    local_user = run("whoami")
    local_host = run("hostname")
    os_name = platform.system()

    all_rows.append({
        "timestamp": now(),
        "source": "whoami",
        "field": "current_user",
        "value": local_user[0].strip(),
        "source_output": ""
    })
    all_rows.append({
        "timestamp": now(),
        "source": "hostname",
        "field": "hostname",
        "value": local_host[0].strip(),
        "source_output": ""
    })
    all_rows.append({
        "timestamp": now(),
        "source": "platform",
        "field": "os",
        "value": os_name,
        "source_output": ""
    })

    if domain:
        # DNS enumeration
        for record in ["_ldap._tcp.dc._msdcs", "_kerberos", "_gc"]:
            cmd = f"nslookup -type=SRV {record} {domain} 2>/dev/null"
            out, err, rc = run(cmd)
            if out.strip():
                all_rows.append({
                    "timestamp": now(),
                    "source": "dns",
                    "field": "record",
                    "value": f"{record}: {out.strip()[:200]}",
                    "source_output": ""
                })

        # DC discovery
        for cmd in [f"nslookup -type=SRV _ldap._tcp.dc._msdcs.{domain} 2>/dev/null",
                    f"nltest /dsgetdc {domain} 2>/dev/null",
                    f"nslookup -type=dc {domain} 2>/dev/null"]:
            out, err, rc = run(cmd)
            if out.strip():
                method = "dns_srv" if "SRV" in cmd else ("nltest" if "nltest" in cmd else "dns_dc")
                all_rows.append({
                    "timestamp": now(),
                    "source": "dc_discovery",
                    "field": "method",
                    "value": f"{method}: {out.strip()[:200]}",
                    "source_output": ""
                })

        # Domain users
        out, err, rc = run("net user /domain 2>&1")
        if out.strip():
            for u in out.strip().splitlines():
                u = u.strip()
                if u:
                    all_rows.append({
                        "timestamp": now(),
                        "source": "net_user_domain",
                        "field": "username",
                        "value": u,
                        "source_output": ""
                    })
        else:
            all_rows.append({
                "timestamp": now(),
                "source": "net_user_domain",
                "field": "error",
                "value": err.strip()[:300],
                "source_output": out.strip()[:500]
            })

        # Domain groups
        out, err, rc = run("net group /domain 2>&1")
        if out.strip():
            for g in out.strip().splitlines():
                g = g.strip()
                if g:
                    all_rows.append({
                        "timestamp": now(),
                        "source": "net_group_domain",
                        "field": "group",
                        "value": g,
                        "source_output": ""
                    })
        else:
            all_rows.append({
                "timestamp": now(),
                "source": "net_group_domain",
                "field": "error",
                "value": err.strip()[:300],
                "source_output": out.strip()[:500]
            })

        # Domain computers
        out, err, rc = run("net computer /domain 2>&1")
        if out.strip():
            for c in out.strip().splitlines():
                c = c.strip()
                if c:
                    all_rows.append({
                        "timestamp": now(),
                        "source": "net_computer_domain",
                        "field": "computer",
                        "value": c,
                        "source_output": ""
                    })
        else:
            all_rows.append({
                "timestamp": now(),
                "source": "net_computer_domain",
                "field": "error",
                "value": err.strip()[:300],
                "source_output": out.strip()[:500]
            })

        # Password policy
        out, err, rc = run("net accounts 2>&1")
        if out.strip():
            for line in out.strip().splitlines():
                line = line.strip()
                if line:
                    all_rows.append({
                        "timestamp": now(),
                        "source": "net_accounts",
                        "field": "policy",
                        "value": line,
                        "source_output": ""
                    })
        else:
            all_rows.append({
                "timestamp": now(),
                "source": "net_accounts",
                "field": "error",
                "value": err.strip()[:300],
                "source_output": out.strip()[:500]
            })

        # GPO / gpresult
        out, err, rc = run("gpresult /scope computer /v 2>/dev/null | head -30")
        if out.strip():
            for line in out.strip().splitlines()[:30]:
                line = line.strip()
                if line:
                    all_rows.append({
                        "timestamp": now(),
                        "source": "gpresult",
                        "field": "gpo",
                        "value": line,
                        "source_output": ""
                    })
        else:
            all_rows.append({
                "timestamp": now(),
                "source": "gpresult",
                "field": "error",
                "value": err.strip()[:300],
                "source_output": out.strip()[:500]
            })

        # Trust relationships
        out, err, rc = run(f"nltest /trusteddomains 2>/dev/null")
        if out.strip():
            for line in out.strip().splitlines():
                line = line.strip()
                if line:
                    all_rows.append({
                        "timestamp": now(),
                        "source": "nltest_trusteddomains",
                        "field": "trust",
                        "value": line,
                        "source_output": ""
                    })
        else:
            all_rows.append({
                "timestamp": now(),
                "source": "nltest_trusteddomains",
                "field": "error",
                "value": err.strip()[:300],
                "source_output": out.strip()[:500]
            })
    else:
        # Local checks - document WORKGROUP environment
        out, err, rc = run("net user /domain 2>&1")
        all_rows.append({
            "timestamp": now(),
            "source": "net_user_domain",
            "field": "local_fail",
            "value": f"rc={rc}",
            "source_output": out.strip()[:500]
        })
        out, err, rc = run("net group /domain 2>&1")
        all_rows.append({
            "timestamp": now(),
            "source": "net_group_domain",
            "field": "local_fail",
            "value": f"rc={rc}",
            "source_output": out.strip()[:500]
        })
        out, err, rc = run("net localgroup administrators 2>&1")
        all_rows.append({
            "timestamp": now(),
            "source": "net_localgroup_admins",
            "field": "local_admins",
            "value": out.strip(),
            "source_output": ""
        })

    return all_rows

def main():
    parser = argparse.ArgumentParser(
        description="AD enumeration helper for learning + internship reporting."
    )
    parser.add_argument(
        "--domain",
        help="FQDN of the domain (e.g. CORP.LOCAL). If omitted, runs local checks."
    )
    parser.add_argument(
        "--output-dir",
        default="AD",
        help="Folder to write CSV results (default: AD)."
    )
    args = parser.parse_args()

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Save host info
    get_host_info(outdir)

    # Collect enumeration data
    all_rows = collect_data(args.domain)

    # Save CSV
    fieldnames = ["timestamp", "source", "field", "value", "source_output"]
    outpath = outdir / "ad_enum_v2.csv"
    with open(outpath, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(all_rows)

    print(f"\nSaved: {outpath}")
    print(f"Total rows: {len(all_rows)}")

if __name__ == "__main__":
    main()
