# AD Enumeration Helper

Lightweight Active Directory enumeration for learning + internship reporting.
Saves domain/user/group/password/policy output to CSV.

## What it does

- Runs `net user /domain`, `net group /domain`, `net computer /domain`, `net accounts`
- Captures whoami, hostname, OS, and user info
- Saves everything to a structured CSV for your portfolio write-up

## Usage

```bash
# Local checks (default)
python ad_enum.py

# Target a domain (if you have one)
python ad_enum.py --domain CORP.LOCAL
```

## Output

- `ad_enum_v2.csv` — structured CSV with: timestamp, source, field, value, source_output
- `host_info.csv` — hostname, OS, Python version, command line

## Scope

Learning utility for internship reporting. Not a security scanner. Only run against
hosts you own or have explicit permission to test.

## Notes

- On a WORKGROUP machine, `net user /domain` and `net group /domain` fail with
  error 1355 ("The specified domain either does not exist or could not be contacted").
  This is a valid finding: the target is not domain-joined.

