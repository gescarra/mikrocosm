#!/usr/bin/env python3
"""
CI artifacts derived from the same topology that builds the routers.

`generate.py` renders what the ROUTERS need. This renders what the PIPELINE
needs, from the identical derived topology, so a change to `topology.yml` moves
the config, the inventory, the test expectations and the pipeline shape in one
step. Adding a third border router shouldn't require anyone to remember to edit
an inventory, a job list and an assertion count by hand. That's precisely the
drift this repo exists to remove, and CI isn't exempt from it.
(Nobody is exempt. Not even CI. Especially not CI.)

Three files, all written to out/, none of them secret:

  manifest.json   what the functional tests EXPECT to find on each router:
                  session names, peer addresses, adjacency counts, the anchors,
                  the customer grants. The tests assert against this instead of
                  hardcoding a fleet that was true when they were written.

  inventory.yml   the Ansible inventory. Every field is derivable from the
                  role, so it's derived rather than maintained: `ansible_host`
                  (the address a control node INSIDE the AS uses),
                  `bootstrap_host` (the failsafe that doesn't depend on the
                  overlay) and `router_role`.

  pipeline.yml    a GitLab child pipeline with one deploy job and one verify job
                  per router, chained in the deliberate br->er->br->er order.
                  The job BODIES live in ci/child-jobs.yml, committed and
                  reviewable; this file is only the list and the wiring.

NOTHING HERE MAY CONTAIN KEY MATERIAL. These three files are CI artifacts: they
land in GitLab's artifact store, which isn't where private keys go. WireGuard
peer publics are represented as truncated SHA-256 fingerprints. Enough for a
test to prove the running config carries the intended peer, without the manifest
itself ever being a thing you have to protect. `test_secrets.py` enforces this.
"""

import hashlib
import ipaddress
import json


# ---------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------
def _fp(public_key):
    """Truncated SHA-256 of a WireGuard public key.

    A fingerprint rather than the key itself, so the manifest stays safe to
    publish as a CI artifact. 16 hex chars is 64 bits. There are 46 keys in
    this fleet, so collision isn't a consideration; readability in a failing
    assertion is."""
    if not public_key:
        return None
    return hashlib.sha256(public_key.encode()).hexdigest()[:16]


def _host_addr(addr):
    """Strip a prefix length and canonicalise: '2001:DB8:0:41::10/64' ->
    '2001:db8:0:41::10'.

    The canonicalisation isn't cosmetic. Tests compare these values against
    what a router prints, and RouterOS prints IPv6 in the canonical compressed
    lowercase form. topology.yml, written by a human, uses uppercase in places.
    So an un-normalised manifest would have a test comparing
    `2001:DB8:0:41::10` to `2001:db8:0:41::10` and reporting a session as
    DOWN while it's established. That failure is indistinguishable from a real
    one at the point you read it."""
    if not addr:
        return None
    bare = addr.split("/")[0]
    try:
        return str(ipaddress.ip_address(bare))
    except ValueError:
        return bare


def deploy_order(d):
    """The rollout order, derived rather than listed.

    Border and edge routers ALTERNATE (br1, er1, br2, er2) so that one BR
    and one ER are up at every step of the roll and the /24 anchor and the /25
    are never both dark at once. That property is the whole reason the order
    can't drift, so it's computed here from the router lists instead of being
    written down somewhere that can fall out of step with them.

    With unequal counts the alternation runs as far as it can and the remainder
    follows: 3 BRs and 2 ERs gives br1, er1, br2, er2, br3. Still never two
    routers of the same role in a row until there's no choice.

    Remote sites go last, unconditionally. A site depends on the BRs for
    reachability itself, so there's nothing to interleave: deploying one can't
    take the core down, and it can't be deployed before the core is up.
    """
    brs, ers = list(d["brs"]), list(d["ers"])
    order = []
    for i in range(max(len(brs), len(ers))):
        if i < len(brs):
            order.append(brs[i])
        if i < len(ers):
            order.append(ers[i])
    return [r["fqdn"] for r in order] + [s["fqdn"] for s in d["sites"]]


def ansible_host(r, topo):
    """The address a control node INSIDE the AS reaches this router on.

    Derived from the role, never listed:

      br    its LOOPBACK, over the tunnels.
      er    its TRANSIT address, NOT a WAN. The ER input chain accepts
            in-interface=<transit> ahead of both the mgmt accept and the WAN
            drops, so that path survives every tunnel being down, BGP being
            dead, and mgmt_prefixes being wrong. It's the break-glass (AD-LOG
            25), it works from inside without touching the overlay, and it's
            therefore better than a loopback here rather than worse.
      sr    its loopback, over the tunnels. A remote ISP address is neither
            static nor reachable. This is why a site's FIRST apply can't
            happen from here: the loopback doesn't exist until the config
            that creates it has been applied.

    >>> THE BORDER ROUTERS USED TO BE REACHED AT THEIR PUBLIC WAN, AND THAT IS
    >>> BROKEN FOR ANY CONTROL NODE INSIDE 203.0.113.0/24.
    >>>
    >>> The ERs statically route each BR's public /32 out their own WAN, because
    >>> a WireGuard endpoint must never resolve through a tunnel. So a request
    >>> from inside leaves via the ISP. The BR then answers using the /25 it
    >>> learns over iBGP: back down a tunnel. Measured on the live fleet:
    >>>
    >>>   er1 -> 198.51.100.57/32  via 172.20.101.1%ether1   (static)
    >>>   br1 -> 203.0.113.7      via wg-er2-wan1           (iBGP, dist 200)
    >>>   br1 -> 192.0.2.190       via 198.51.100.1%ether1   (default)
    >>>
    >>> That last line is why a laptop OUTSIDE the AS works and an on-prem
    >>> runner doesn't: an outside source has no specific route on the BR, so
    >>> the reply follows the default straight back out the provider and the
    >>> path is symmetric.
    >>>
    >>> The BR's choice isn't the bug. Answering an in-AS source down a
    >>> tunnel is correct, and the alternative is out to the internet and back
    >>> into our own announcement. The asymmetry comes from the request leaving
    >>> the other way, and the static /32 that causes it has to stay.
    >>>
    >>> So: inside the AS, use the address that belongs to the AS. Verified
    >>> symmetric in both directions. It also makes every deploy prove the
    >>> overlay came back before the rollout moves on, which is a gate the WAN
    >>> address silently skipped. `bootstrap_host` keeps the public address for
    >>> the cases that genuinely need it. See below.
    """
    if r["role"] == "br":
        return r["loopback"]
    if r["role"] == "er":
        return topo["home"][f"transit_er{r['index']}"]
    return r["loopback"]


def bootstrap_host(r, topo):
    """The address that works when the overlay does NOT, or from outside the AS.

    For a border router that's its provider WAN: static (AD-LOG 17), and the
    only address it has before a single tunnel exists. Every other role already
    uses an address that doesn't depend on the overlay, so for them this is
    the same value `ansible_host` returns.

    This is the failsafe, not the default. Reach for it when a BR's tunnels are
    down and you need in anyway, or when the control node is outside the AS.
    A laptop on somebody else's network is the case `ansible_host` can't
    serve. Pass `-e use_bootstrap=true` to Ansible, or `--bootstrap` to the
    functional suite.

    If neither works, the answer is the provider console; see ansible/README.md.
    """
    if r["role"] == "br":
        return r["wan_address"]
    return ansible_host(r, topo)


# ---------------------------------------------------------------------
#  The manifest: what the tests expect to find
# ---------------------------------------------------------------------
def _peer_on_31(addr):
    """The other address in a /31 (or /127).

    Both ends of a point-to-point link are the two addresses in one /31, so the
    far end is derivable from the near one by flipping the last bit. Derived
    rather than looked up on the far router: the MTU probe needs it on a site
    router whose peer's manifest entry isn't in scope, and this is the same
    arithmetic that placed the addresses in the first place."""
    if not addr:
        return None
    a = ipaddress.ip_address(addr)
    return str(ipaddress.ip_address(int(a) ^ 1))


def _tunnel_entry(t, peer_fqdn):
    return {
        "iface":        t["iface"],
        "peer_router":  t["peer_router"],
        "peer_fqdn":    peer_fqdn,
        "link_class":   t["link_class"],
        "address":      _host_addr(t["address"]),
        "address6":     _host_addr(t.get("address6")),
        # The far end of the link, for the data-plane and MTU probes.
        "peer_address":  _peer_on_31(_host_addr(t["address"])),
        "peer_address6": _peer_on_31(_host_addr(t.get("address6"))),
        "listen_port":  t["listen_port"],
        # Set only on the end that dials. The listening end has no endpoint,
        # which is itself worth asserting: a BR that grew an endpoint toward an
        # ER would mean the NAT-piercing direction got inverted.
        "endpoint":     t.get("endpoint"),
        "peer_key_fp":  _fp(t.get("peer_public")),
    }


def _peer_field(d, name, field):
    """One field off the peer record `name`, or None.

    The per-BR link records carry the tunnel; the peer record carries the
    policy. Both are needed to describe a session, and this keeps the lookup
    in one place rather than threading the peer list through every caller.
    """
    for p in d.get("peers") or []:
        if p.get("name") == name:
            return p.get(field)
    return None


def _router_entry(r, topo, d, by_name):
    """One router's expectations. Role-agnostic parts first, then the parts
    that only make sense for a border, edge or site router."""
    v6 = d["v6"]
    m = {
        "fqdn":         r["fqdn"],
        "name":         r["name"],
        "role":         r["role"],
        "site":         r["site"] if r["role"] != "sr" else r.get("name"),
        "index":        r["index"],
        "ansible_host":   ansible_host(r, topo),
        "bootstrap_host": bootstrap_host(r, topo),
        "loopback":     _host_addr(r["loopback"]),
        "loopback6":    _host_addr(r["loopback6"]) if v6 else None,
        "config_file":  f"{r['fqdn']}.rsc",
    }

    # ---- WireGuard -------------------------------------------------
    # A BR carries its backbone links in a separate list from its tunnels; both
    # are WireGuard interfaces running OSPF, so both belong here. Flattening
    # them is what lets one assertion cover "every tunnel this router should
    # have" without the test needing to know the difference.
    tunnels = [_tunnel_entry(t, by_name.get(t["peer_router"], {}).get("fqdn"))
               for t in r["tunnels"]]
    tunnels += [_tunnel_entry(t, by_name.get(t["peer_router"], {}).get("fqdn"))
                for t in r.get("backbone", [])]
    m["tunnels"] = tunnels

    # ---- OSPF ------------------------------------------------------
    # One adjacency per OSPF-speaking interface. Every tunnel runs OSPF; an ER
    # additionally runs it over the physical er1<->er2 cross-connect, which is
    # not a tunnel and so isn't in the list above.
    #
    # This is `>=` in the tests, not `==`: a router that has MORE adjacencies
    # than expected is a topology question, not a deploy failure, and failing
    # the roll on it would block the very deploy that brings the count back in
    # line. Fewer is the failure.
    ospf_ifaces = [t["iface"] for t in tunnels]
    if r["role"] == "er":
        ospf_ifaces.append(r["xc_interface"])
    m["ospf_interfaces"] = ospf_ifaces
    m["ospf_neighbors_expected"] = len(ospf_ifaces)

    # ---- iBGP ------------------------------------------------------
    # Full mesh: every router peers with every other, so the session list IS
    # the fleet minus self. Names mirror the templates (ibgp-<peer>, ibgp6-<peer>).
    m["ibgp"] = [{
        "session":  f"ibgp-{p['name']}",
        "session6": f"ibgp6-{p['name']}" if v6 else None,
        "peer":     p["name"],
        "peer_fqdn": p["fqdn"],
        "address":  _host_addr(p["loopback"]),
        "address6": _host_addr(p["loopback6"]) if v6 else None,
    } for p in r["ibgp_peers"]]

    # ---- role-specific ---------------------------------------------
    if r["role"] == "br":
        m["ebgp"] = [{
            "session": "ebgp-upstream",
            "address": _host_addr(r["peer_address"]),
            "asn":     r["peer_asn"],
            "family":  4,
        }]
        if v6 and r.get("peer_v6_address"):
            m["ebgp"].append({
                "session": "ebgp6-upstream",
                "address": _host_addr(r["peer_v6_address"]),
                "asn":     r["peer_asn"],
                "family":  6,
            })
        m["provider"]    = r["provider"]
        m["wan_address"] = r["wan_address"]
        m["wan_gateway"] = r["wan_gateway"]
        # The origination anchors. A blackhole at distance 254 whose PRESENCE is
        # what makes the BR announce the aggregate (output.network only sends a
        # network that resolves), which is why a test that reads these is
        # reading the origination switch itself and not a proxy for it.
        m["anchors"] = [{"comment": "anchor", "prefix": topo["prefix"], "family": 4}]
        if v6:
            m["anchors"].append({"comment": "anchor6",
                                 "prefix": topo["aggregate_v6"], "family": 6})
        m["originates"] = [topo["prefix"]] + ([topo["aggregate_v6"]] if v6 else [])
        # An upstream that stops sending a default is a BR with no egress, and
        # nothing else on the box reports it: iBGP still works, OSPF stays Full.
        m["expect_default"] = {"v4": True, "v6": bool(v6 and r.get("peer_v6_address"))}

        # ---- external peers ----------------------------------------
        # A SEPARATE key from m["ebgp"], deliberately: the functional test
        # that asserts the upstream session is established must keep meaning
        # exactly what it means today, and a peer isn't an upstream.
        #
        # The most valuable assertion this enables is the NEGATIVE one.
        # Test that no peer-learned prefix appears in the advertisements
        # toward ebgp-upstream. That proves settlement-free on the wire
        # rather than in the config, which is the only place it counts.
        m["peers"] = [{
            "name":     l["peer"],
            "realm":    l["realm"],
            "transport": l["transport"],
            "iface":    l["iface"],
            "session":  f"peer-{l['peer']}",
            "session6": f"peer6-{l['peer']}",
            "instance": _peer_field(d, l["peer"], "instance"),
            "vrf":      _peer_field(d, l["peer"], "vrf"),
            "asn":      _peer_field(d, l["peer"], "asn"),
            "endpoint": l.get("endpoint"),
            # Truncated SHA-256, like every other public key in this file.
            # A peer's WireGuard public key isn't secret, but the manifest
            # having exactly one shape for "a key was here" is worth more
            # than the raw value nobody reads.
            "peer_key_fp": _fp(l.get("peer_public")),
            "address":  (l.get("v4") or {}).get("remote"),
            "address6": (l.get("v6") or {}).get("remote"),
            "max_routes":    _peer_field(d, l["peer"], "max_routes"),
            "max_routes_v6": _peer_field(d, l["peer"], "max_routes_v6"),
            "cone": [{"prefix": c["prefix"], "min_len": c["min_len"],
                      "max_len": c["max_len"], "family": c["family"]}
                     for c in (_peer_field(d, l["peer"], "claims") or [])
                     + (_peer_field(d, l["peer"], "claims6") or [])],
        } for l in r.get("peers", [])]

        # The tables that must NOT be the main one. A functional test reads
        # these and asserts the realm's routes are in its own table and
        # nowhere else: the isolation property, checked on the box.
        m["vrfs"] = sorted({p["vrf"] for p in m["peers"] if p["vrf"]})
        m["rpki"] = sorted(g["group"] for g in (d.get("rpki") or {}).values()
                           if g.get("usable"))

    elif r["role"] == "er":
        m["transit_interface"] = r["transit_interface"]
        m["transit_ip"]  = _host_addr(topo["home"][f"transit_er{r['index']}"])
        m["transit_ip6"] = _host_addr(r["transit_ip6"]) if v6 else None
        m["xc_interface"] = r["xc_interface"]
        m["customers"] = [{
            "name":     fw["name"],
            "session":  f"cust-{fw['name']}",
            "session6": f"cust6-{fw['name']}" if (v6 and fw["claims6"]) else None,
            "address":  _host_addr(fw["peer_address"]),
            "address6": _host_addr(fw.get("peer_address_v6")) if v6 else None,
            "asn":      fw["asn"],
            "bfd":      bool(fw["bfd"]),
            # The grants, flattened to what a test can check a received route
            # against: this prefix, at a length in this range, and nothing else.
            "claims":   [{"prefix": c["prefix"], "min_len": c["min_len"],
                          "max_len": c["max_len"], "family": c["family"]}
                         for c in fw["claims"] + (fw["claims6"] if v6 else [])],
        } for fw in r["firewalls"]]
        m["anchors"] = [
            {"comment": "home-anchor", "prefix": topo["blocks"]["customer_home"],
             "family": 4},
            {"comment": "loop guard", "prefix": topo["prefix"], "family": 4},
        ]
        if v6:
            m["anchors"] += [
                {"comment": "home-anchor6",
                 "prefix": topo["blocks_v6"]["customer_home"], "family": 6},
                {"comment": "loop guard v6", "prefix": topo["aggregate_v6"],
                 "family": 6},
            ]
        m["originates"] = ([topo["blocks"]["customer_home"]]
                           + ([topo["blocks_v6"]["customer_home"]] if v6 else []))
        # An ER has no default of its own: it learns one over iBGP from the BRs
        # once the tunnels and sessions are up. Which makes it a REAL test.
        # A missing default here means the whole stack below it failed.
        m["expect_default"] = {"v4": True, "v6": bool(v6)}

    else:  # remote site
        m["delegation"]    = r["delegation"]
        m["delegation_v6"] = r.get("delegation6")
        m["lan_gateway"]   = r.get("lan_gateway")
        m["lan_interfaces"] = r.get("lan_interfaces", [])
        m["anchors"] = []
        m["originates"] = []
        m["expect_default"] = {"v4": True, "v6": bool(v6)}

    # ---- BFD -------------------------------------------------------
    # Only meaningful once BOTH switches are on: `configure` alone permits
    # sessions without asking for any, which is pass 1 of the documented
    # two-pass rollout and must not be asserted as if it were pass 2.
    bfd = topo.get("bfd") or {}
    m["bfd"] = {
        "expect_ospf_sessions": bool(bfd.get("configure") and bfd.get("use_ospf")),
        "customer_sessions": ([fw["name"] for fw in r["firewalls"] if fw["bfd"]]
                              if r["role"] == "er" else []),
    }
    return m


def build_manifest(topo, d, pinned=None):
    """Everything the pipeline and the functional tests need, and nothing a
    private key would fit in."""
    by_name = {r["name"]: r for r in d["brs"] + d["ers"] + d["sites"]}
    routers = {r["fqdn"]: _router_entry(r, topo, d, by_name)
               for r in d["brs"] + d["ers"] + d["sites"]}

    v6 = d["v6"]
    home = topo["blocks"]["customer_home"]

    return {
        # Schema version, so a test suite from an older commit fails loudly on a
        # manifest it doesn't understand instead of silently skipping the
        # assertions whose keys got renamed.
        # 2: adds the external-peering keys (peers/vrfs/rpki on a BR). Bumped
        # rather than added silently so an older functional suite fails loudly
        # instead of skipping assertions it doesn't know exist.
        "schema": 2,
        "asn": topo["asn"],
        "prefix": topo["prefix"],
        "prefix_v6": topo.get("prefix_v6"),
        "aggregate_v6": topo.get("aggregate_v6"),
        "v6": v6,
        "customer_home": home,
        "customer_home_v6": topo.get("blocks_v6", {}).get("customer_home"),
        "domain": topo.get("domain"),
        "wg_mtu": topo["wg_mtu"],
        "mss_clamp": topo["mss_clamp"],
        "mss_clamp_v6": topo.get("mss_clamp_v6"),
        "deploy_order": deploy_order(d),
        "loopbacks": {r["fqdn"]: _host_addr(r["loopback"])
                      for r in d["brs"] + d["ers"] + d["sites"]},
        "loopbacks_v6": ({r["fqdn"]: _host_addr(r["loopback6"])
                          for r in d["brs"] + d["ers"] + d["sites"]} if v6 else {}),
        "routers": routers,

        # ---- what the end-to-end test proves ------------------------
        # The runner sits at hdc BEHIND the customer firewalls, so its own
        # egress traverses exactly the path this whole build exists to provide:
        # firewall -> ER -> tunnel -> BR -> upstream -> internet, and back down
        # the same stack. Two things make that a test rather than a ping:
        #
        #  - the SOURCE address the internet sees must be inside our /24. That
        #    single assertion proves the return half of the path independently
        #    of the outbound half: the /24 is in the DFZ, someone is
        #    originating it, and the packets are coming back to US.
        #  - a large TLS transfer, not an ICMP echo. A wrong mss_clamp gives you
        #    a network where ping is perfect and every real connection stalls,
        #    and ICMP will never find it.
        "e2e": {
            "egress_must_be_in": topo["prefix"],
            "egress_must_be_in_v6": topo.get("aggregate_v6"),
            "runner_should_be_in": home,
            "origin_asn": topo["asn"],
        },

        # ---- who the pipeline logs in as ----------------------------
        # Named here so it's stated once. CI reads it from this file rather
        # than carrying its own copy in a GitLab variable. Two places naming
        # the login is two places to forget when it changes, and the symptom
        # would be a permission error that reads like a dead router.
        #
        # No keys: the public half is committed in topology.yml where it can be
        # reviewed, and there's nothing an artifact gains by copying it.
        "automation": ({"user": (topo["automation"] or {}).get("user"),
                        "group": (topo["automation"] or {}).get("group")}
                       if topo.get("automation") else None),

        # ---- pinned build-time fetches ------------------------------
        # generate.py reaches out to two URLs at RENDER time: the management
        # SSH keys and the mgmt_prefixes floor-union endpoint. A pipeline that
        # renders in one job and deploys in another would re-fetch, and a change
        # at either endpoint in between means the config that ships isn't the
        # config that passed. Pinning freezes both into an artifact the deploy
        # job renders from, which is what makes the pipeline hermetic.
        "pinned": pinned or {},
    }


def write_manifest(manifest, path):
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------------
#  The Ansible inventory
# ---------------------------------------------------------------------
def render_inventory(manifest):
    """The inventory, derived.

    Only the STRUCTURE is generated. Hosts, the address to reach each one at,
    and its role. Operational variables (SSH options, timeouts, the user) stay
    in ansible/group_vars/all.yml where they are committed, reviewable, and
    overridable with -e; they are choices about how to drive a rollout, not
    facts about the topology, and generating them would put a hand-tuned
    timeout inside a file that gets overwritten by the next build.
    """
    order = manifest["deploy_order"]
    lines = [
        "# =====================================================================",
        "#  GENERATED by generate.py from topology.yml -- DO NOT EDIT.",
        "#",
        "#  Host keys are router FQDNs, which are also the generated config",
        "#  filenames (out/<fqdn>.rsc), so inventory_hostname drives both the",
        "#  file we upload and the identity we verify after the reset.",
        "#",
        "#  Host ORDER is the rollout order. Don't reshuffle it: border and",
        "#  edge routers alternate so one of each stays up at every step. Keep",
        "#  serial:1 + order:inventory in any playbook that uses this.",
        "#",
        "#  ansible_host is the address for a control node INSIDE the AS, which",
        "#  is where the runner lives. bootstrap_host is the failsafe that does",
        "#  not depend on the overlay (a border router's provider WAN); use it",
        "#  with -e use_bootstrap=true. See ansible_host() in emit.py for why a",
        "#  BR's public address does not work from inside 203.0.113.0/24.",
        "#",
        "#  Operational vars (SSH opts, timeouts, router_user) live in",
        "#  ansible/group_vars/all.yml -- committed, not generated.",
        "# =====================================================================",
        "all:",
        "  children:",
        "    routers:",
        "      hosts:",
    ]
    for fqdn in order:
        r = manifest["routers"][fqdn]
        lines.append(f"        {fqdn}:")
        lines.append(f"          ansible_host: {r['ansible_host']}")
        if r["bootstrap_host"] != r["ansible_host"]:
            lines.append(f"          bootstrap_host: {r['bootstrap_host']}"
                         f"   # failsafe: -e use_bootstrap=true")
        else:
            lines.append(f"          bootstrap_host: {r['bootstrap_host']}")
        lines.append(f"          router_role: {r['role']}")
        lines.append(f"          loopback: {r['loopback']}")
        if r.get("loopback6"):
            lines.append(f"          loopback6: {r['loopback6']}")
        # A hAP-class site router has 16 MB of flash IN TOTAL, so upgrade.yml's
        # 25 MB floor (sized for CHR images) can never pass on one, and its
        # "clear old files first" message sends you looking for space that does
        # not exist. Derived from the role because the role is what implies the
        # hardware class.
        if r["role"] == "sr":
            lines.append("          min_free_bytes: 8000000   # hAP-class: 16 MB flash total")
    # Group the roles so a playbook can say `hosts: br` without re-deriving it.
    for role in ("br", "er", "sr"):
        members = [f for f in order if manifest["routers"][f]["role"] == role]
        if members:
            lines.append(f"    {role}:")
            lines.append("      hosts:")
            for f in members:
                lines.append(f"        {f}: {{}}")
    return "\n".join(lines) + "\n"


def write_inventory(manifest, path):
    path.write_text(render_inventory(manifest))


# ---------------------------------------------------------------------
#  The GitLab child pipeline
# ---------------------------------------------------------------------
def render_pipeline(manifest):
    """One deploy job and one verify job per router, chained in rollout order.

    The job BODIES aren't here. They live in ci/child-jobs.yml, which is
    committed and reviewed like any other code; this file only names the routers
    and wires the `needs:` chain. Generating shell would put the part most
    likely to need debugging in the part nobody reads.

    The chain is strictly linear and every link is `needs:`, so a failing verify
    stops the roll where it stands: router N+1 is never touched because the job
    that would touch it never becomes eligible. That's the gate the whole
    design turns on, and it's expressed as a DAG edge rather than as a check
    inside a script that could be skipped.
    """
    order = manifest["deploy_order"]

    # Every job needs the parent pipeline's build artifacts. manifest.json
    # (what to assert), inventory.yml (what to compare against) and pin.json
    # (the frozen fetches to re-render from). A child pipeline reaches them
    # through `needs: pipeline:`, and because a job's own `needs:` REPLACES the
    # inherited one, this has to appear in every generated job rather than once
    # in ci/child-jobs.yml.
    parent = "    - pipeline: $PARENT_PIPELINE_ID\n      job: build"

    lines = [
        "# =====================================================================",
        "#  GENERATED by generate.py from topology.yml -- DO NOT EDIT.",
        "#",
        "#  The rollout, one router at a time, in the alternating br->er order",
        "#  that keeps one border and one edge router up at every step.",
        "#",
        "#  Every step is a `needs:` edge, so this is a chain and not a stage",
        "#  fan-out: verify:<router> failing means deploy:<next router> never",
        "#  becomes eligible to run. The gate is the DAG.",
        "#",
        "#  Job bodies: ci/child-jobs.yml (committed).",
        "# =====================================================================",
        "include:",
        "  - local: ci/child-jobs.yml",
        "",
        # ONE stage for the whole chain, deliberately.
        #
        # GitLab only lets `needs:` reference a job in the SAME or an EARLIER
        # stage. This chain interleaves. Deploy, verify, deploy, verify.
        # So deploy and verify can't be separate ordered stages: the second
        # deploy would need a verify that lives in a later one, and the
        # pipeline is refused at creation with
        #   `need verify:br1.ord1 isn't defined in current or prior stages`.
        #
        # Putting them all in one stage costs nothing, because the `needs:`
        # edges ARE the ordering here. Stages would only re-state it, less
        # precisely. chaos stays separate purely so it sits visually apart in
        # the UI as the manual step it's.
        "stages: [rollout, chaos]",
        "",
    ]

    # The pre-flight. Deliberately the first thing in the child pipeline rather
    # than the parent's: it's part of the rollout's safety, and it must run
    # against the fleet as it's RIGHT NOW, not as it was when the build ran.
    lines += [
        "# The fleet must be healthy BEFORE we touch it. A roll that starts on a",
        "# network already missing an OSPF adjacency will blame the first router",
        "# it deploys for a fault that predates the pipeline -- and, worse, will",
        "# have destroyed the evidence by resetting the box.",
        "baseline:",
        "  extends: .baseline",
        "  needs:",
        parent,
        "",
    ]

    prev = "baseline"
    for fqdn in order:
        r = manifest["routers"][fqdn]
        dep, ver = f"deploy:{fqdn}", f"verify:{fqdn}"
        lines += [
            f"{dep}:",
            "  extends: .deploy_router",
            "  variables:",
            f"    ROUTER: {fqdn}",
            f"    ROUTER_ROLE: {r['role']}",
            "  needs:",
            f"    - {prev}",
            parent,
            "",
            f"{ver}:",
            "  extends: .verify_router",
            "  variables:",
            f"    ROUTER: {fqdn}",
            f"    ROUTER_ROLE: {r['role']}",
            "  needs:",
            f"    - {dep}",
            parent,
            "",
        ]
        prev = ver

    # The whole-fleet end-to-end run. The per-router gates already ran this
    # test (it's the most important one, so it gates every step) but a
    # final pass with the full fleet converged is what the pipeline's green
    # tick actually means.
    lines += [
        "e2e:",
        "  extends: .e2e",
        "  needs:",
        f"    - {prev}",
        parent,
        "",
        "# Opt-in. Breaks a live path on purpose to prove the failover documented",
        "# in docs/failure-modes.md is real, then puts it back. Manual because",
        "# the right time to run it is when you are watching, not on every merge.",
        "chaos:",
        "  extends: .chaos",
        "  needs:",
        "    - e2e",
        parent,
        "",
    ]
    return "\n".join(lines)


def write_pipeline(manifest, path):
    path.write_text(render_pipeline(manifest))
