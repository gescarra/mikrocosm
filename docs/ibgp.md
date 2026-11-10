# Layer 2/3 — iBGP and eBGP

BGP is where the routes live. OSPF ([ospf.md](ospf.md)) gives internal reachability. iBGP uses it
to carry customer prefixes across the AS and eBGP trades routes with the two upstreams.

## Why iBGP *over* OSPF, and not just OSPF

OSPF could redistribute the customer prefixes. It isn't allowed to, for two reasons:

1. **Policy.** Customer prefixes need per-prefix policy: communities, RTBH tagging, selective
   origination, upstream prepending. OSPF has none of that vocabulary. BGP is built for it. Keep
   customer routes in BGP and OSPF stays a small, fast, purely topological IGP that reconverges in
   milliseconds and never carries a policy decision.
2. **Next-hop semantics.** iBGP advertises a prefix with the **originator's loopback** as next-hop
   and every other router resolves that loopback *recursively through OSPF*. The prefix and the
   path to it are computed separately. iBGP says "er1 has the `/25`." OSPF says "here's the best
   path to er1 right now." If that path moves (wan1 → backbone → sibling ER) the route follows on
   its own and BGP re-advertises nothing.

Division of labour: **OSPF = where the routers are. iBGP = what routes exist and what policy they
carry.**

## Full mesh, not route reflection

Every router runs an iBGP session to every other router. Six routers → 15 sessions. **No route
reflector.** That's a correctness call, not just a scaling one.

### Why not RR: the forwarding loop

Origination needs `nexthop-choice=force-self`. A router advertising a prefix it originates must set
the next-hop to *itself* so peers resolve it to the right place. But **RFC 4456 says an RR leaves
NEXT_HOP alone on reflected routes**, so `force-self` on an RR is invalid.

Make the BRs RRs for the ERs *and* full-mesh among themselves, and you get:

- br1 reflects er1's `/25` to br2 with next-hop `br1-lo`;
- br2 reflects er1's `/25` to br1 with next-hop `br2-lo`;
- br1 sees `br2-lo` at IGP cost **5** (backbone) vs `er1-lo` at **10**, so it prefers the sibling;
- br2 does the same → **br1 → br2 → br1 forwarding loop.**

CLUSTER_LIST won't save you. It stops *advertisement* loops, not this forwarding loop.

### Why full mesh fixes it

In a full mesh **nothing is reflected**. A router never re-advertises an iBGP-learned route to
another iBGP peer. So `force-self` is correct everywhere, applied only by the router that
*originates* a prefix. Every router sees every prefix with the true originator's next-hop and
resolves it through OSPF. No loop possible.

Revisit route reflection around 12+ routers. If you do, configure it right: RRs preserve next-hop
and only originators force-self. (`local.role` has no `ibgp-rr-client` value anyway. The valid
roles are `ibgp` and `ibgp-rr`.)

## What each router originates

Only the originator applies `force-self`, so who originates what is the whole game:

| Router | Originates into iBGP | How |
|---|---|---|
| **ER** (er1, er2) | `203.0.113.0/25`, the home customer block | `output.network=advertise` list gated by a blackhole `home-anchor`. `home-anchor-guard` toggles it on live-VIP presence so it withdraws when no firewall is delivering |
| **BR** (br1, br2, …) | the eBGP-learned **default route** | propagated so the ERs know which BR to egress through. Every BR's copy is identical unless `te.local_pref` separates them ([traffic-engineering.md](traffic-engineering.md)) |
| **remote-site router** (`sr1.<site>`) | that site's `/29`, and its `/48` in v6 | same pattern: advertise what's attached. The `/29` is gated on its connected route (LAN down → withdrawn). The `/48` on a blackhole anchor because in v6 the LAN is just one `/64` of it |

A site router is a full-mesh member like any other. It holds a tunnel to **every** BR, peers with
every BR, every ER and every other site, and never gets pinned to a "primary" border router. The BRs
give it a default the same way they give one to an ER (`default-originate=if-installed` on the
downstream sessions, gated by `default-guard`). The ERs treat it like a BR on output, so it gets the
home `/25` aggregate and none of the customer VIP more-specifics.

What the BRs **don't** put into iBGP: the `203.0.113.0/24` aggregate. Both ERs' and BRs' output
filters `reject` the `/24` explicitly. The `/24` goes *only* toward the upstreams and *only* from
each BR's local anchor. Never internally. Leaking it into iBGP would send in-block traffic with no
specific route to a BR that'll just drop it. See [origination.md](origination.md).

## The three-object BGP model (RouterOS specifics)

RouterOS v7 splits one BGP session across three menus. Put a property in the wrong one and it's
quietly rejected or quietly inherited:

| Object | Owns | Notes |
|---|---|---|
| `/routing/bgp/instance` | `router-id`, `as`, `cluster-id`, `multipath`, `vrf` | **Not legacy.** Delete it and your router-id goes with it. `router-id` lives *only* here. `multipath` comes from `bgp_multipath` and stops two identical defaults collapsing to a router-id tie-break. It's a **count**, not a switch. `multipath=yes` aborts the import. See [traffic-engineering.md](traffic-engineering.md). |
| `/routing/bgp/template` | `afi` (not `address-families`), `multihop`, `nexthop-choice`, `input.*`/`output.*` filters | Carries **no** `local.*`/`remote.*`/`router-id`. |
| `/routing/bgp/connection` | `local.address`, `local.role`, `remote.address`, `remote.as`, `listen`, `connect` | Per-session, so they repeat on every connection. |

Two traps that look like "healthy sessions that route nothing":

- **Leave the `default` template bare.** A connection with no `templates=` inherits `default`. Leave
  anything policy-shaped there and an iBGP session inherits it. It comes up, tries to originate the
  `/24`, refuses to carry the default and everything *looks* fine. Both templates set `default`
  empty on purpose.
- **Pin `local.address`** (WAN address on eBGP, loopback on iBGP). Unset, RouterOS guesses the
  highest loopback and the upstream stops recognising the session.

Full rationale for each: [AD-LOG.md §6.4](../AD-LOG.md).

## The edge: eBGP {#the-edge-ebgp}

Each BR runs one eBGP session to its upstream. The two upstreams, Vultr (AS64515) and HostHatch
(AS65473), **both peer at the same multihop address `169.254.169.254` with different ASNs.** It's
the easiest thing in the build to get wrong. Symptom: a session stuck in `Active` with nothing in
the log.

Each eBGP session does two things:

- **Outbound:** originates `203.0.113.0/24` (via the anchor, see [origination.md](origination.md)),
  applies per-upstream community and prepend policy and strips internal large communities on the
  way out. That policy includes the static `te.prepend` that steers ingress
  ([traffic-engineering.md](traffic-engineering.md)). The output chain **ends in `reject`** so an
  untagged more-specific can never leak upstream.
- **Inbound:** accepts *only* the default route (`0.0.0.0/0`) and rejects everything else. That
  default then goes into iBGP so the ERs learn their egress.

Two static routes make this safe:

- The peer `169.254.169.254/32` is pinned via the provider gateway. Otherwise the eBGP session
  could try to resolve its peer through the default it's learning from that peer. Permanent
  recursion flap.
- The provider's DHCP default sits at `distance=250`. It's there so the BR stays manageable. Never
  preferred, never advertised. A BR with dead eBGP has to **stop** promising a default to the ERs
  or the provider drops the redirected traffic at its prefix filter.

Upstream communities and RTBH get their own doc: [communities-rtbh.md](communities-rtbh.md).

---

**Next:** [Origination & the anchor →](origination.md). How the `/24` gets out and stays out.
