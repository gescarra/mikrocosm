"""
End to end: on-prem firewall -> public internet.

The most important test here, and the only one that exercises what the network
is actually for. Everything in test_router.py asks a router about itself. This
asks the internet about us.

IT RUNS ON THE CONTROL NODE, NOT ON A ROUTER, and that's the whole design. The
GitLab runner sits at hdc BEHIND the customer firewalls, so its own egress
traverses the entire stack without simulating any of it:

    runner -> pfSense/UniFi -> ER -> WireGuard -> BR -> upstream -> internet
                                                                      |
    and back down the same stack, which only works if the /24 is <-----+
    in the DFZ and somebody is originating it.

Two assertions carry almost all the weight, and they are the two that a router
can't make about itself:

  THE SOURCE ADDRESS THE INTERNET SEES IS INSIDE OUR /24.
    This proves the RETURN half of the path independently of the outbound half.
    Traffic can leave through anything; it comes back to 203.0.113.0/24 only
    if the prefix is globally routed, an anchor is up, an upstream is carrying
    it, and the tunnels deliver it home. One HTTP GET tests all of that. A
    default route leaked in from somewhere else would still give you working
    internet: and a different source address, which is what makes this the
    assertion rather than the ping.

  A LARGE TLS TRANSFER COMPLETES.
    A wrong MSS clamp produces a network where ICMP is flawless, DNS is
    instant, small requests work, and anything that fills a window stalls
    forever. No ping will ever find it. This will.

Run it from somewhere behind the firewalls, or it's testing somebody else's
internet connection. `--no-e2e` skips the module for a control node that's
not placed there.
"""

import ipaddress
import socket
import subprocess
import urllib.error
import urllib.request

import pytest

# All read-only GETs of public information. The reflectors return OUR OWN
# public address (that response IS the assertion) and nothing about this
# host is sent to them.
REFLECTORS_V4 = ["https://api.ipify.org", "https://ipv4.icanhazip.com"]
REFLECTORS_V6 = ["https://api6.ipify.org", "https://ipv6.icanhazip.com"]
PING_V4 = ["1.1.1.1", "8.8.8.8"]
PING_V6 = ["2606:4700:4700::1111", "2001:4860:4860::8888"]
DNS_NAMES = ["one.one.one.one", "www.google.com"]

# Big enough that a wrong clamp stalls it rather than merely slowing it.
BULK_URL = "https://speed.cloudflare.com/__down?bytes=8000000"
BULK_MIN_BYTES = 8_000_000

RIS_URL = "https://stat.ripe.net/data/routing-status/data.json?resource="


@pytest.fixture(autouse=True)
def _skip_when_disabled(pytestconfig):
    if pytestconfig.getoption("--no-e2e"):
        pytest.skip("--no-e2e: control node is not behind the customer firewalls")


@pytest.fixture(scope="session")
def e2e(manifest):
    return manifest["e2e"]


@pytest.fixture(scope="session")
def vantage(e2e):
    """Where this control node is standing, as far as it can tell.

    The end-to-end assertion is only meaningful from BEHIND the customer
    firewalls, and that can't be fully self-detected. A host NATted to a VIP
    looks the same from the inside as a host somewhere else entirely. What can
    be detected is whether this host holds an address out of the customer /25,
    and that's enough to decide which cause a failure should LEAD with. Getting
    that order wrong means a developer running the suite from a laptop is told
    their /24 has been withdrawn.
    """
    addrs = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, family):
                addrs.add(info[4][0])
        except socket.gaierror:
            pass
    for family in (socket.AF_INET, socket.AF_INET6):
        got = _has_global_address(family)
        if got:
            addrs.add(got)
    inside = sorted(a for a in addrs
                    if _in_network(a, e2e["runner_should_be_in"]))
    return {"addresses": sorted(addrs), "inside": inside,
            "behind_firewall": bool(inside)}


# Some CDNs answer a bare urllib request with 403. Cloudflare's speed endpoint
# does. That produced a "transfer failed" that the test then blamed on the MSS
# clamp: a tooling problem reported as a network fault, which is the one
# direction these messages must never go.
UA = "as64500-netdevops-e2e/1 (+https://github.com/)"


def _get(url, timeout=20):
    req = urllib.request.Request(
        url, headers={"Accept": "text/plain", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode().strip()


def _ping_argv(family, target):
    """`ping6 -W` doesn't exist on macOS, and `-W` means different things on
    different pings. Drop it and let the subprocess timeout do the bounding.
    Portability matters here because the control node is a Linux container in
    CI and somebody's laptop when they are debugging."""
    cmd = "ping" if family == 4 else "ping6"
    return [cmd, "-c", "3", target]


def _has_global_address(family):
    """Can this host originate traffic in this family at all?

    Asked by opening a UDP socket, which routes without sending anything. A
    control node with no IPv6 is a fact about the control node; failing the
    IPv6 test for it would report the network as broken because the laptop is
    on a v4-only LAN.
    """
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.connect(("2606:4700:4700::1111" if family == socket.AF_INET6
                   else "1.1.1.1", 53))
        addr = s.getsockname()[0]
        s.close()
        return addr
    except OSError:
        return None


def _first_reflector(urls):
    """The first reflector that answers. Errors are collected rather than
    raised so a single dead service isn't reported as a network outage."""
    errors = []
    for url in urls:
        try:
            return _get(url), errors
        except Exception as exc:                      # noqa: BLE001
            errors.append(f"{url}: {exc}")
    return None, errors


# ---------------------------------------------------------------------
#  Where are we standing?
# ---------------------------------------------------------------------
def test_report_where_this_control_node_sits(e2e, vantage):
    """Deliberately informational, never an assertion.

    Whether inside hosts hold /25 addresses directly or are NATted to a VIP is
    the firewall operator's choice, and this build doesn't write that box. The
    egress test below settles it either way: whichever it's, the address the
    internet sees has to be ours.
    """
    print(f"\nControl node addresses: {vantage['addresses'] or 'unknown'}")
    if vantage["behind_firewall"]:
        print(f"  inside {e2e['runner_should_be_in']}: {vantage['inside']} "
              f"-- this is the real customer path.")
    else:
        print(f"  none inside {e2e['runner_should_be_in']}. Fine if the "
              f"firewall NATs inside hosts to a VIP. NOT fine if this node is "
              f"not at hdc at all, because then these tests are measuring "
              f"somebody else's internet connection.")


def _in_network(addr, cidr):
    try:
        return ipaddress.ip_address(addr) in ipaddress.ip_network(cidr)
    except ValueError:
        return False


# ---------------------------------------------------------------------
#  The basics, in the order that makes a failure readable
# ---------------------------------------------------------------------
def test_dns_resolves():
    resolved = []
    for name in DNS_NAMES:
        try:
            socket.getaddrinfo(name, None)
            resolved.append(name)
        except socket.gaierror:
            pass
    assert resolved, (
        f"No name resolved ({', '.join(DNS_NAMES)}). The routers themselves "
        f"resolve through public anycast and never through internal DNS, so "
        f"this is about the control node's resolver -- but it also fails when "
        f"egress is dead, so read the ICMP result before blaming DNS.")


@pytest.mark.parametrize("family,targets", [(4, PING_V4), (6, PING_V6)])
def test_icmp_reaches_the_internet(family, targets, manifest):
    if family == 6 and not manifest["v6"]:
        pytest.skip("topology is v4-only")
    af = socket.AF_INET if family == 4 else socket.AF_INET6
    if not _has_global_address(af):
        pytest.skip(
            f"this control node has no IPv{family} address of its own, so "
            f"this would be testing the control node rather than the network")
    ok = []
    for t in targets:
        try:
            proc = subprocess.run(_ping_argv(family, t),
                                  capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                ok.append(t)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    assert ok, (
        f"No IPv{family} target answered ({', '.join(targets)}). "
        + ("Nothing behind the firewall has egress right now."
           if family == 4 else
           "IPv4 is unaffected and nothing else complains, which is precisely "
           "why this is a separate assertion -- half the network can be down "
           "for weeks without anyone noticing."))


# ---------------------------------------------------------------------
#  THE test
# ---------------------------------------------------------------------
def test_the_internet_sees_us_as_our_own_prefix(e2e, vantage):
    egress, errors = _first_reflector(REFLECTORS_V4)
    assert egress, (
        f"No address reflector answered:\n  " + "\n  ".join(errors) + "\n"
        f"ICMP passed, so this is more likely the services than the network -- "
        f"but it could also be TCP specifically, which is what a broken MSS "
        f"clamp looks like. Check the bulk-transfer result.")

    network_causes = (
        f"  - the firewall is not sending through the edge routers\n"
        f"  - the edge routers are not reaching the border routers\n"
        f"  - the /24 is no longer originated, and the return path arrives "
        f"somewhere else entirely\n"
        f"Check in this order:\n"
        f"  /routing/bgp/session print       on both ERs (customer sessions)\n"
        f"  /ip/route print where blackhole  on both BRs (is the anchor "
        f"enabled?)\n"
        f'  /log print where message~"anchor-guard"')

    # WHICH CAUSE COMES FIRST MATTERS. This test is only meaningful from behind
    # the customer firewalls, and the commonest way to see it fail is to run it
    # from somewhere else. Leading with "your /24 has been withdrawn" when the
    # real answer is "you are on a laptop" is how a gate stops being believed.
    if not vantage["behind_firewall"]:
        assert _in_network(egress, e2e["egress_must_be_in"]), (
            f"Egress is {egress}, which is NOT inside "
            f"{e2e['egress_must_be_in']} -- but READ THIS FIRST:\n\n"
            f"This control node holds no address in "
            f"{e2e['runner_should_be_in']} "
            f"(it has {vantage['addresses']}), so it is probably not behind "
            f"the customer firewalls at all, and this test is measuring "
            f"somebody else's internet connection. That is the likeliest "
            f"explanation by far, and it is not a network fault.\n\n"
            f"Run it from the on-prem runner, or pass --no-e2e.\n\n"
            f"If this IS the on-prem runner, then it is one of:\n"
            + network_causes)
    else:
        assert _in_network(egress, e2e["egress_must_be_in"]), (
            f"END-TO-END FAILED. This control node is inside "
            f"{e2e['runner_should_be_in']} ({vantage['inside']}), so it is in "
            f"the right place -- and traffic from it leaves as {egress}, which "
            f"is NOT inside {e2e['egress_must_be_in']}.\n\n"
            f"Egress itself works, so this is not 'the internet is down'. It "
            f"is that we are not using our own space:\n" + network_causes)
    print(f"\nEND-TO-END OK — the internet sees us as {egress}, inside "
          f"{e2e['egress_must_be_in']}. The whole path is up in both "
          f"directions.")


def test_ipv6_egress_uses_our_announced_aggregate(e2e, manifest):
    if not manifest["v6"]:
        pytest.skip("topology is v4-only")
    egress, errors = _first_reflector(REFLECTORS_V6)
    if not egress:
        pytest.skip(
            "no IPv6 reflector answered; if this control node's LAN has no "
            f"IPv6 that is expected. Errors: {errors}")
    assert _in_network(egress, e2e["egress_must_be_in_v6"]), (
        f"IPv6 egress is {egress}, not inside "
        f"{e2e['egress_must_be_in_v6']}.\n"
        f"Note the aggregate we ANNOUNCE is deliberately smaller than the /40 "
        f"ARIN allocated -- an address inside the /40 but outside the /42 "
        f"means something is sourcing from unannounced space.")


def test_a_large_tls_transfer_completes(manifest):
    """The fault ICMP can never find."""
    mtu_hint = (
        f"Suspect MTU/MSS before anything else: wg_mtu is "
        f"{manifest['wg_mtu']}, the v4 clamp is {manifest['mss_clamp']} and "
        f"the v6 clamp is {manifest['mss_clamp_v6']}. A clamp that is too high "
        f"gives exactly this -- the handshake succeeds, the first full-size "
        f"segment never arrives, and the connection hangs rather than failing.")

    try:
        req = urllib.request.Request(BULK_URL, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as resp:
            size = len(resp.read())
    except urllib.error.HTTPError as exc:
        # The server ANSWERED and said no. That isn't an MTU problem, and
        # saying it's sends someone to binary-search a working tunnel. This
        # test previously blamed the clamp for a plain 403 caused by a missing
        # User-Agent; a gate that misattributes its own faults to the network
        # is worse than no gate.
        pytest.fail(
            f"The bulk-transfer endpoint returned HTTP {exc.code} "
            f"({exc.reason}) for {BULK_URL}.\n"
            f"The server answered, so the path works and this is the TEST's "
            f"problem, not the network's -- pick another BULK_URL or send the "
            f"headers it wants. Do NOT read this as an MTU fault.",
            pytrace=False)
    except Exception as exc:                          # noqa: BLE001
        # No answer, or the connection died mid-body. THIS is the shape a
        # broken clamp makes.
        pytest.fail(
            f"A {BULK_MIN_BYTES}-byte HTTPS transfer failed: {exc}\n\n"
            f"If ping and DNS passed and this did not, {mtu_hint}",
            pytrace=False)

    assert size >= BULK_MIN_BYTES, (
        f"Only {size} of {BULK_MIN_BYTES} bytes arrived. The path does not "
        f"carry full-size segments end to end -- test_router.py proves the "
        f"tunnel MTU on the routers, so if that passed and this did not, the "
        f"clamping on the FIREWALL is the remaining suspect.\n" + mtu_hint)
    print(f"\n{size} bytes over TLS -- the path carries full-size segments, "
          f"so the MSS clamp is right end to end.")


# ---------------------------------------------------------------------
#  Advisory
# ---------------------------------------------------------------------
def test_report_dfz_visibility(manifest, e2e, record_property):
    """Is the prefix visible from outside, from the right origin?

    ADVISORY, NOT A GATE, and the reason matters. RIS aggregates over a window
    and lags reality by minutes to hours, so wiring a rollout to it produces
    red pipelines for a network that's entirely fine. And a gate that cries
    wolf is a gate that gets bypassed.

    It's also nearly redundant: the egress assertion above already proves the
    prefix is globally routed and returning to us, in real time. This adds the
    one thing that can't: WHO the DFZ thinks is originating it. Worth
    printing every run, worth reading, not worth blocking on.
    """
    import json
    try:
        doc = json.loads(_get(RIS_URL + manifest["prefix"], timeout=25))
    except Exception as exc:                          # noqa: BLE001
        print(f"\nRIPE RIS did not answer ({exc}); advisory check skipped.")
        return

    origins = [str(o.get("origin")) for o in doc["data"].get("origins", [])]
    record_property("dfz_origins", ",".join(origins))
    expected = str(e2e["origin_asn"])
    print(f"\nRIS sees {manifest['prefix']} originated by "
          f"AS{', AS'.join(origins) or '(nothing)'} (expected AS{expected}).")
    if origins and expected not in origins:
        print("  !! THE ORIGIN IS NOT OURS. Investigate before ignoring this.")
