# Layer 1 — OSPF

OSPF runs over the WireGuard tunnel `/31`s, plus the loopbacks and the home local links. It has two
jobs. Only two:

1. **Liveness detection.** Noticing a link died.
2. **Internal reachability.** A path from every router to every other router's loopback, which is
   what iBGP next-hops resolve through.

OSPF carries **no customer prefixes**. Those ride iBGP ([ibgp.md](ibgp.md)). Keeping the jobs apart
is on purpose. OSPF knows the *internal graph*. iBGP knows the *routes*.

## Why OSPF is the only liveness detector

**A WireGuard interface never goes down by itself.** No carrier, no link state. Pull the plug on the
far end and the local `wg` interface stays `up` forever, happily accepting packets into a black
hole. Nothing at the interface layer will ever tell you the tunnel is dead.

So liveness has to come from a protocol that swaps periodic hellos across the tunnel and tears the
adjacency down when they stop. That's OSPF. **Hellos flowing means the path works end to end. Hellos
stopped means it's gone.** Everything downstream keys off that adjacency state:

- iBGP next-hops that resolved via a dead tunnel go unreachable and BGP re-selects.
- `anchor-guard`'s isolation signal is literally "can I still reach any AS peer's loopback in the
  OSPF-fed routing table" (see [origination.md](origination.md)).

That's why the tunnels are point-to-point OSPF (`type=ptp`) with explicit, fairly tight hello/dead
timers. Nothing relies on what WireGuard reports.

WireGuard is a great tunnel and a terrible witness. Ask it whether the other end is alive and it'll
cheerfully tell you about the last handshake, which could have been yesterday.

## BFD — the same signal, three orders of magnitude faster

OSPF can't notice faster than `dead-interval`: **20 s** on the backbone and wan1, **40 s** on wan2
and the ER interconnect. A long time to blackhole customer traffic into a tunnel that's already dead.

**BFD ([RFC 5880](https://www.rfc-editor.org/rfc/rfc5880)) is a hello protocol that does exactly the
liveness job above and nothing else.** No adjacency, no LSAs, no route computation. So it can run at
sub-second intervals where an OSPF hello can't. When the session drops it tells OSPF and the
adjacency tears right away instead of waiting out `dead-interval`.

| Link | OSPF dead-interval | BFD interval × multiplier | Detects in |
|---|---|---|---|
| BR ↔ BR backbone | 20 s | 200 ms × 3 | **~600 ms** |
| BR ↔ ER over **wan1** | 20 s | 300 ms × 4 | **~1.2 s** |
| BR ↔ ER over **wan2** | 40 s | 1 s × 5 | **~5 s** |
| er1 ↔ er2 interconnect | 40 s (default) | 100 ms × 3 | **~300 ms** |

Four deliberate choices here.

**BFD is additive. The OSPF timers don't change.** Every `hello-interval`/`dead-interval` in the
templates is what it was. If a BFD session fails to come up for any reason the network falls back to
exactly today's behaviour, not to *no* detection. That's what makes it safe to turn on.

**One interval per link class, mirroring the cost table.** The classes are physically different
media. Along with wan2's OSPF timers, this is the other thing that depends on what the link *is*.
The backbone is **not** at 100 ms on purpose. Both BRs are CHR guests on shared VPS hosts, where a
few hundred milliseconds of hypervisor scheduling delay is normal and would flap a tighter session.
wan2 is slow for the same reason its OSPF timers are. It's CGNAT'd 5G, and flapping on mobile jitter
is worse than catching a failure late. `generate.py` refuses to render any class that detects in
under ~50 ms.

**Sessions are default-deny.** RouterOS forbids BFD on any interface not listed in
`/routing/bfd/configuration`, so a BR's upstream-facing `ether1` is excluded without a rule. The
ERs' customer transit segment is the one exception and gets its own section
[below](#bfd-toward-the-customer-firewalls).

**Each family gets its own session.** OSPFv3 neighbours are link-local IPv6 addresses so each link
carries a v4 and a v6 BFD session. The configuration entries match on *interface*, not family, so
both inherit the same class timers. Same reason the v4 and v6 costs are identical.

### Rolling it out

Two `topology.yml` switches. **Order matters.**

```yaml
bfd:
  configure: true     # pass 1 — permit BFD + set timers. Inert on its own.
  use_ospf:  false    # pass 2 — put use-bfd=yes on the OSPF templates.
```

`configure` only *permits* sessions. Nothing creates one until `use_ospf` asks. `deploy.yml` rolls
one router at a time behind a manual gate, so arming both at once leaves a long window where one
router asks peers for BFD they still forbid. Deploy pass 1 everywhere first. Then flip `use_ospf`
and deploy again. `generate.py` refuses `use_ospf: true` without `configure: true`.

Verify:

```
/routing/bfd/session/print
/routing/ospf/neighbor/print detail
```

Every session should be `U` (up) with its class's `desired-tx-interval`. Stuck at `packets-rx=0`?
The far end hasn't had pass 1.

## BFD toward the customer firewalls

Everything above is BFD under OSPF on tunnels that already had a 20–40 s detector. The ER↔firewall
eBGP sessions never had one. They run on RouterOS's default BGP **hold time of 3 minutes**. For three
minutes after a firewall dies the ERs keep its VIPs installed, keep advertising them to each other
and keep the `/25` anchor originated, because the route is still there. Two firewalls advertising
the same VIP *is* the failover. And there's no failover until the dead one's session drops.

Turning it on takes a third switch and a per-firewall flag:

```yaml
bfd:
  configure: true
  customer: { interval: 300ms, multiplier: 3 }   # permits BFD on the transit segment

firewalls:
  - name: fwa
    bfd:  true                                   # asks for it, on THIS firewall's sessions
```

`bfd.customer` swaps the transit interface's `forbid-bfd=yes` for a permit. `bfd: true` puts
`use-bfd=yes` on that firewall's v4 and v6 BGP connections. Detection drops from ~180 s to
**~900 ms**.

**300 ms, not the interconnect's 100 ms**, because the far end isn't a MikroTik. pfSense runs FRR's
`bfdd` as a userspace process on a general-purpose OS that's also doing NAT and IDS. A busy firewall
isn't a dead firewall. A VIP that withdraws during a big download is worse than one that withdraws a
second late. And 300 ms is FRR's default too so both ends agree untuned.

**The flag is per firewall on purpose.** This build doesn't write the far end, so "BFD works here" is
a fact about one machine. Flag one, watch it through a real failure, then flag the next. Meanwhile
the unflagged firewall carries the same VIPs on the old timers.

### Order, and it's the reverse of the tunnel rollout

Both tunnel ends were ours, so the safe order was configure everywhere then arm everywhere. Here one
end belongs to someone else:

1. Set `bfd.customer` with every `bfd:` flag still false → deploy **both** ERs. The transit interface
   now permits BFD. Nothing on the wire changes.
2. On pfSense: **System → Package Manager → FRR**, then **Services → FRR → BFD** to enable `bfdd`,
   then tick BFD on **one** ER neighbour under **BGP → Neighbors**. FRR's 300 ms / 300 ms / 3
   defaults already match. Check that BGP session is still up before ticking the second ER. Nobody
   has verified whether FRR holds a session down while its BFD has never come up. One neighbour at a
   time means the other ER keeps carrying the VIPs if it does.
3. `bfd: true` on that firewall → `./build.sh` → deploy the ERs.
4. Leave the second firewall unflagged until the first has survived a failure.

`generate.py` refuses `bfd: true` without `bfd.customer` and `bfd.customer` without `configure`. It
also refuses the flag on a firewall whose config this build renders, unless that renderer emits a BFD
stanza. `unifi` doesn't, so the two ends would disagree.

Verify on the ER:

```
/routing/bfd/session/print
/routing/bgp/session/print where remote.address=203.0.113.236
```

Two sessions per flagged firewall, v4 and v6. The eBGP sessions are separate and BFD sessions are
keyed on family. **Nobody has exercised `use-bfd` on `/routing/bgp/connection` on this fleet yet.**
Confirm a live ER accepts the property before the first deploy. `deploy.yml` imports after a
`reset-configuration` and one rejected line leaves the router with no BGP at all.

## The cost model *is* the WAN preference

**WAN preference is only OSPF cost. BGP never mentions which WAN is primary.** Promoting the backup
WAN is a two-line cost change. Not a reconfiguration.

| Link | Cost | Hello / Dead |
|---|---|---|
| BR ↔ BR backbone | **5** | 5s / 20s |
| BR ↔ ER over **wan1** (primary) | **10** | 5s / 20s |
| BR ↔ ER over **wan2** (backup) | **100** | 10s / 40s |
| er1 ↔ er2 interconnect | **1** | — |

Two rules behind these numbers.

**The backbone cost (5) must never let the backbone steal traffic from a direct path.** Worked
examples:

- `br1 → br2` direct = **5** vs. `br1 → er1 → br2` = 10 + 10 = 20. Direct wins. ✓
- `er1 → br2` direct = **10** vs. `er1 → br1 → br2` = 10 + 5 = 15. Direct wins. ✓
- `er1 → br2` when er1's wan1 tunnel to br2 is down: `er1 → er2 → br2` = 1 + 10 = **11**, still beats
  wan2's **100**. Traffic reroutes *via the sibling ER over wan1* and doesn't drop to wan2. Correct.
  wan2 is a last resort, not a second choice. ✓

**wan2's timers are looser on purpose** (10s/40s vs 5s/20s). It's a jittery mobile link and
aggressive timers would flap the adjacency on normal jitter. On a stable backup you'd tighten them to
match wan1. This is one of two things that depend on what wan2 *physically is*. See the
media-agnostic discussion in [AD-LOG.md §7.1](../AD-LOG.md). The same reasoning sets wan2's BFD
interval.

## Area design

Everything sits in one backbone area (`area 0.0.0.0`). Loopbacks and the firewall transit interface
are `passive`: advertised, no adjacency. The tunnel `/31`s and the ER interconnect form adjacencies.
Six routers don't justify multi-area anything.

## What a healthy router sees

A BR should have **7** OSPF adjacencies: 2 ER-wan1 + 2 ER-wan2 + 3 backbone. Fewer means a tunnel is
down. Per the failure model that's the early warning to alert on (see
[failure-modes.md](failure-modes.md) and [AD-LOG.md §11](../AD-LOG.md)).

Once BFD is armed `/routing/bfd/session` should count **twice** the adjacencies, one per family per
adjacency. A BFD session that's present but down while its OSPF adjacency is up is the signature of a
one-sided rollout.

---

**Next layer:** [iBGP →](ibgp.md). What rides on top of the reachability OSPF provides.
