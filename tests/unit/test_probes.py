"""
The RouterOS probe, tested without a RouterOS.

The probe is one string sent to a router over ssh. Getting it wrong doesn't
produce an error anyone reads. It produces an EMPTY probe, and every
assertion downstream then reports a perfectly healthy network as dead. That's
the worst possible failure for a deployment gate: it stops a rollout, it looks
exactly like an outage, and the evidence points at the network rather than at
the tool.

This is also the test that would have caught the bug that motivated moving the
probes out of Ansible YAML in the first place: a folded YAML scalar keeps the
newline on any line indented further than its block, and a newline landing
inside a `:do { }` block cuts the command in half. Building the probe in Python
means it can be asserted offline, on every merge, in milliseconds.
"""

import json
import re

import pytest

from tests.functional.routeros import (ERROR, IMPORT_ERROR_PATTERNS,
                                       INTERACTIVE_MARK, MARK, as_bool,
                                       build_probe, import_error_query,
                                       parse_probe)


# ---------------------------------------------------------------------
#  Shape
# ---------------------------------------------------------------------
def test_probe_is_a_single_line():
    """The whole reason this file exists.

    The probe goes to ssh as ONE argv element. A newline inside a `:do { }`
    block or a parenthesised expression is a RouterOS syntax error, and the
    symptom is silence rather than a complaint.
    """
    probe = build_probe(["203.0.113.0/28"])
    assert "\n" not in probe, "the probe contains a newline"
    assert "\r" not in probe


def test_probe_needs_no_shell_quoting():
    """No shell is involved on either side. Python passes argv directly and
    RouterOS isn't a POSIX shell. Backticks and `$(...)` would still be worth
    knowing about if they ever appeared, because somebody will eventually paste
    one of these into a terminal to debug it."""
    probe = build_probe()
    assert "`" not in probe
    assert "$(" not in probe


def test_every_section_is_individually_error_trapped():
    """One unknown property must cost one section, not the whole probe.

    Without the trap, a property renamed in a future RouterOS release takes
    down every check at once and the failure reads as a total outage.
    """
    probe = build_probe(["203.0.113.0/28"])
    opens = probe.count(":do {")
    traps = probe.count("on-error=")
    assert opens == traps, (
        f"{opens} guarded expressions but {traps} error handlers; a section "
        f"can abort the probe")
    assert probe.count(ERROR) == traps


def test_all_expected_sections_are_present():
    probe = build_probe()
    for section in ("identity", "version", "logerr", "ospf", "bgp",
                    "wg_peers", "wg_ifaces", "bfd",
                    "default4", "default6", "blackhole4", "blackhole6"):
        assert f"{MARK}{section} " in probe, f"no {section} section"


def test_serialize_is_used_for_every_table():
    """Structured JSON, not string concatenation. This is the whole reason the
    probes moved off `:put` with `.` concatenation. And it's what the REST
    API would otherwise have been needed for."""
    probe = build_probe()
    assert probe.count(":serialize to=json") >= 8
    assert "print as-value" in probe


# ---------------------------------------------------------------------
#  The customer-claim sections are driven by the manifest
# ---------------------------------------------------------------------
def test_claims_produce_one_section_each():
    probe = build_probe(["203.0.113.0/28", "203.0.113.17/32"])
    assert f"{MARK}claim0 " in probe
    assert f"{MARK}claim1 " in probe
    assert "dst-address in 203.0.113.0/28" in probe
    assert "dst-address in 203.0.113.17/32" in probe


def test_no_claim_sections_without_grants():
    """A border router holds no customer space and must not be asked about
    any: an empty result there would be indistinguishable from a real one."""
    probe = build_probe()
    assert f"{MARK}claim0 " not in probe


def test_claims_negate_blackhole_the_only_way_that_works():
    """`!blackhole`, never `blackhole=no`.

    RouterOS leaves the property UNSET on a route that isn't a blackhole, so
    `blackhole=no` matches nothing: it returns zero rows for a table full of
    healthy routes, silently. Verified against a live 7.24 edge router carrying
    a customer route: `blackhole=no` gave 0, `!blackhole` gave 1.

    The same mistake was in anchor-guard, where it would have withdrawn the
    /24. See test_render.py's predicate check, which now guards the rendered
    configs against it too."""
    probe = build_probe(["203.0.113.0/28"])
    assert "&& active && !blackhole" in probe
    assert "blackhole=no" not in probe


def test_import_error_patterns_all_reach_the_log_query():
    probe = build_probe()
    for pattern in IMPORT_ERROR_PATTERNS:
        assert f'message~"{pattern}"' in probe, (
            f"{pattern!r} is listed as an import failure but never queried")


# ---------------------------------------------------------------------
#  Parsing
# ---------------------------------------------------------------------
def test_parses_tables_and_scalars():
    out = parse_probe(
        f'{MARK}identity br1.ord1\n'
        f'{MARK}logerr 0\n'
        f'{MARK}bgp [{{"remote.address":"203.0.113.241","established":"true"}}]\n'
    )
    assert out["identity"] == "br1.ord1"
    assert out["logerr"] == "0"
    assert out["bgp"][0]["remote.address"] == "203.0.113.241"


def test_a_failed_section_stays_distinguishable_from_an_empty_one():
    """The distinction the whole error-trap design exists for. "I couldn't
    ask" and "the answer is none" are different facts, and conflating them
    turns a tooling problem into a fake outage."""
    out = parse_probe(f'{MARK}bgp {ERROR}\n{MARK}ospf []\n')
    assert out["bgp"] == ERROR
    assert out["ospf"] == []


def test_unparseable_json_is_reported_as_an_error_not_as_empty():
    out = parse_probe(f'{MARK}bgp [{{"broken": \n')
    assert out["bgp"] == ERROR


def test_noise_around_the_sections_is_ignored():
    """RouterOS prints a banner on login, and some builds add a trailing
    prompt. Neither is a section."""
    out = parse_probe(
        "\r\n  MikroTik RouterOS 7.23.2 (c) 1999-2025\r\n"
        f"{MARK}identity er1.hdc\n"
        "[netops@er1.hdc] > \n")
    assert out == {"identity": "er1.hdc"}


# ---------------------------------------------------------------------
#  RouterOS booleans
# ---------------------------------------------------------------------
@pytest.mark.parametrize("value,expected", [
    (True, True), (False, False),
    ("true", True), ("false", False),
    ("yes", True), ("no", False),
    ("", False), (None, False),
])
def test_boolean_coercion_accepts_both_serialisations(value, expected):
    """`:serialize` emits booleans as strings unless
    `options=json.no-string-conversion` is set, and which one you get has
    varied across releases. Accepting both is cheaper than depending on it."""
    assert as_bool(value) is expected


# ---------------------------------------------------------------------
#  The probe is valid enough to round-trip
# ---------------------------------------------------------------------
def test_a_realistic_router_reply_parses_into_usable_state():
    """A worked example, in the shape RouterOS actually returns. Doubles as
    documentation of what the assertions in test_router.py are reading."""
    reply = "\n".join([
        f"{MARK}identity br1.ord1",
        f"{MARK}version 7.23.2 (stable)",
        f"{MARK}logerr 0",
        f"{MARK}ospf " + json.dumps([
            {"state": "Full", "interface": "wg-er1-wan1"},
            {"state": "Full", "interface": "wg-er1-wan2"},
        ]),
        f"{MARK}bgp " + json.dumps([
            {"name": "ibgp-er1", "remote.address": "203.0.113.249",
             "established": "true"},
            {"name": "ebgp-upstream", "remote.address": "169.254.169.254",
             "established": "false"},
        ]),
        f"{MARK}blackhole4 " + json.dumps(
            [{"dst-address": "203.0.113.0/24", "blackhole": "true",
              "disabled": "false"}]),
    ])
    state = parse_probe(reply)

    assert state["identity"] == "br1.ord1"
    assert int(state["logerr"]) == 0
    assert sum(1 for n in state["ospf"] if n["state"] == "Full") == 2

    up = {s["remote.address"] for s in state["bgp"]
          if as_bool(s["established"])}
    assert up == {"203.0.113.249"}
    assert "169.254.169.254" not in up, (
        "a session with established=false must not count as up -- this is the "
        "coercion that decides whether a dead upstream is reported")

    assert not any(as_bool(r["disabled"]) for r in state["blackhole4"])


# ---------------------------------------------------------------------
#  Import errors vs. errors somebody typed
# ---------------------------------------------------------------------
# Both of these are real, copied from br1.ord1's log.
REAL_IMPORT_ERROR = (
    "error while running run-after-reset script: Script Error: missing "
    "value(s) of argument(s) password (/user/add; line 144)")
REAL_ADHOC_ERROR = (
    "(ssh-cmd:gitlab-runner@203.0.113.236) expected end of command "
    "(line 1 column 114)")


def _matches(query, message):
    """Evaluate the probe's `where` clause against one message.

    Mirrors RouterOS's semantics for the shape this query has. A disjunction
    of `message~"..."` tests, ANDed with an optional negated one. Substring is
    the right model: none of the patterns contain regex metacharacters, which
    `test_the_patterns_stay_plain_substrings` keeps true.
    """
    body, _, tail = query.partition(") && ")
    negated = tail.startswith("!")
    pats = re.findall(r'message~"([^"]+)"', body)
    tag = re.findall(r'message~"([^"]+)"', tail)[0]
    hit = any(p in message for p in pats)
    return hit and ((tag not in message) if negated else (tag in message))


def test_a_real_import_failure_is_counted():
    """The failure this gate exists for. If this stops matching, a router can
    come back half-configured and the pipeline will call it healthy."""
    assert _matches(import_error_query(), REAL_IMPORT_ERROR)


def test_a_real_typo_is_not_counted():
    """br1 carried two of these and its config was correct. Counting them
    failed the baseline of a healthy fleet."""
    assert not _matches(import_error_query(), REAL_ADHOC_ERROR)


def test_the_two_queries_partition_the_same_errors():
    """Every matching error is counted by exactly one of the two. So nothing
    is silently dropped by being neither."""
    for msg in (REAL_IMPORT_ERROR, REAL_ADHOC_ERROR):
        counted = _matches(import_error_query(), msg)
        adhoc = _matches(import_error_query(interactive=True), msg)
        assert counted != adhoc, f"{msg!r} is counted by {counted=} {adhoc=}"


def test_an_unrecognised_error_source_still_counts():
    """The denylist direction, asserted.

    An error from a source neither this test nor the query anticipated (a
    scheduler, a netwatch script, something in a future RouterOS) must land
    in the GATING count. Red for an unknown reason is recoverable; green for
    an unknown reason is how a half-applied router ships.
    """
    assert _matches(import_error_query(),
                    "(script:watchdog) bad command name foo")


def test_the_patterns_stay_plain_substrings():
    """`message~` is a REGEX match on the router. A pattern containing `(`,
    `[` or `|` would quietly mean something else there than it does in the
    substring model above: and than whoever added it intended."""
    for p in IMPORT_ERROR_PATTERNS + (INTERACTIVE_MARK,):
        assert not (set(p) & set(r"()[]|*+?^$\\")), (
            f"{p!r} contains regex metacharacters; it is used as a regex on "
            f"the router and as a substring in the tests, and those stop "
            f"agreeing here")
