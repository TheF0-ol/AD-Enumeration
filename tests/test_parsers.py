"""Parser tests for ad_enum.py (parse_names).

Feeds simulated net-command output into parse_names() and checks the results.
Run with:  python -m pytest tests/test_parsers.py -v
"""

import sys
import os

# Make the active folder importable (the script lives next to this file)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ad_enum import parse_names


# ---------------------------------------------------------------------------
# Simulated sample output (based on the format of Windows net commands).
# TODO: replace with real captures from the lab domain once available.
# ---------------------------------------------------------------------------
NET_USER_OUTPUT = """\
The request will be processed at a domain controller for domain CORP.LUCID.

-------------------------------------------------------------------------------
Administrator
  Comment = Administrator
  Full Name = Administrator
  Local Account = Yes
  Password never expires = Yes
---------------------------------------------------------------------
Guest
  Comment = Gasto
  Full Name = Gasto
  Local Account = Yes
  Password never expires = Yes
---------------------------------------------------------------------
The command completed successfully.
"""

# Simulated `net group "Domain Admins" /domain` Members section
NET_GROUP_OUTPUT = """\
Alias name     Domain Admins

Comment        Group used to administer the domain

Members

-------------------------------------------------------------------------------
Administrator  Domain Admins  Enterprise Admins
---------------------------------------------------------------------
The command completed successfully.
"""


def test_parse_net_user_returns_admin_and_guest():
    names = parse_names(NET_USER_OUTPUT)
    assert "Administrator" in names
    assert "Guest" in names
    # Attributes such as "Comment = Administrator" are NOT names
    assert "Comment = Administrator" not in names


def test_parse_net_user_skips_header_and_footer():
    names = parse_names(NET_USER_OUTPUT)
    assert "The request will be processed" not in names
    assert "The command completed successfully." not in names
    assert "CORP.LUCID" not in names


def test_parse_net_group_returns_members():
    names = parse_names(NET_GROUP_OUTPUT)
    assert "Administrator" in names
    assert "Enterprise Admins" in names
    assert "Domain Admins" in names


def test_parse_net_user_empty_block():
    """A block with no lines between dashes returns an empty list."""
    out = """\
---------------------------------------------------------------------
---------------------------------------------------------------------
The command completed successfully.
"""
    assert parse_names(out) == []


def test_parse_net_user_error_output():
    """The 1355 error case returns an empty list (no names to parse)."""
    out = """\
The request will be processed at a domain controller for domain CORP.LUCID.

System error 1355 has occurred.

The specified domain either does not exist or could not be contacted.
"""
    assert parse_names(out) == []


def test_parse_single_name():
    """A single account line after a dash separator."""
    out = """\
-------------------------------------------------------------------------------
Administrator
---------------------------------------------------------------------
The command completed successfully.
"""
    assert parse_names(out) == ["Administrator"]
