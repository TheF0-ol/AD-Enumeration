# AD Enumeration Helper

Two read-only Active Directory enumeration scripts for a domain-joined
Windows host, both tested against a real lab Active Directory domain
(Windows Server 2022 DC + Windows 11 client), not just simulated output.

- **`ad_enum.py`** — focused tool: domain users and the groups you ask for,
  parsed into a clean CSV (one row per account/member).
- **`ad_enum_v2.py`** — broader tool: domain controller discovery, users,
  groups, computer accounts, password policy, a GPO summary, and trust
  relationships, all in one structured CSV.

Both require **no administrator rights** — every command they run is a
normal read-only query any authenticated domain user can make.

## Usage

```bash
# Focused tool
python ad_enum.py
python ad_enum.py --domain corp.local --groups "Domain Admins,Domain Users"

# Broader tool
python ad_enum_v2.py --domain corp.local --output-dir results
```

## Tested on

Both scripts were run as a normal, non-admin domain user (not Administrator)
against a real lab environment:
- A Windows Server 2022 domain controller, promoted to a single-domain forest
- A Windows 11 Enterprise client joined to that domain
- Host-only virtual network, fully isolated from the internet

Real, unmodified output from both runs is in `samples/`.

**Bugs this real-world test actually found and fixed in `ad_enum_v2.py`:**
- `nslookup -type=SRV` queries against the `_msdcs` subdomain consistently
  timed out on a real DC; `nltest /dsgetdc` already returns the same
  discovery info (site, GUID, capability flags) reliably, so the redundant,
  unreliable DNS query was dropped rather than patched.
- `net computer /domain` is not a valid way to list computer accounts —
  real output showed `net computer` is actually for adding/removing a
  single computer, not listing them. Fixed to use
  `net group "Domain Computers" /domain` instead, which correctly returns
  computer accounts (recognizable by their trailing `$`, e.g. `DC-01$`).
- `nltest /trusteddomains` is not a real nltest option; real output showed
  it just printed the command's usage text. Fixed to `nltest /domain_trusts`.

**Expected, not a bug:** `gpresult /scope computer /v` returns
`ERROR: Access Denied` when run as a non-admin domain user, since reading
computer-scope GPO data needs local admin rights on the machine. The
script records this result rather than treating it as a failure to hide,
since "GPO details aren't readable as a standard user" is itself a useful
observation for a write-up.

## Tests

```bash
python -m pytest tests/test_parsers.py -v
```

6 tests against `ad_enum.py`'s parser, run with simulated sample data
matching the real `net user`/`net group` output format confirmed above.

## Known limitations

- Output parsing assumes English-language Windows.
- `ad_enum.py` only enumerates users and the groups you request;
  `ad_enum_v2.py` adds DC discovery, computers, password policy, GPO
  summary and trusts, but does not enumerate OUs, GPO *links*, or ACLs.
- Neither script requires or uses admin rights, so GPO contents and some
  deeper AD details are intentionally out of scope.

## Disclaimer

For learning and authorized testing only. Run only on systems you own or
have explicit written permission to test.
