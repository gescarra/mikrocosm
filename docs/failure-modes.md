# Failure behaviour

Every failure walked through the three mechanisms in [origination.md](origination.md). **Debugging
an outage? Find the matching row and work outward from it.**

Watch the **"/24 in the global table"** column. It says whether the outside world sees the prefix
at all. The promise is that it reads *Announced* through every home failure and *Withdrawn* only
when nothing in the AS can deliver.

The internet only finds out you had a bad day if it was a *really* bad day.

| Event | /24 in the DFZ | What happens and why |
|---|---|---|
| **Steady state** | Announced (all BRs) | The ERs' iBGP `/25` (next-hop = ER loopback) beats every BR's `/24` blackhole on longest-prefix-match. Traffic reaches home. |
| **Home blip / maintenance (< 10 min)** | **Announced. No flap.** | ER iBGP sessions drop → `/25` withdrawn → BRs fall back to their blackhole and drop home traffic for the duration. The global table sees nothing. **This is the case the whole design exists for.** |
| **Home down > 10 min, no remote sites** | **All BRs withdraw** | The no-customer guard fires (10 min). Nothing in the AS can deliver anything so withdrawing is correct. |
| **Home down > 10 min, a remote site alive** | **Announced** | The site's `/29` is an active customer prefix on **every** BR. The site router originates it into the full iBGP mesh, so it's everyone's route and not just "its own BR's". The no-customer guard never fires. **The site keeps working while home is dark.** |
| **br1 loses all home tunnels; backbone OK** | Announced | br1's iBGP to the ERs is loopback-to-loopback. OSPF resolves `er1-lo` **via br2 across the backbone** so the sessions survive and br1 keeps the `/25`. It forwards home traffic through br2, one extra DC hop. No withdrawal, no blackhole. |
| **br1 loses home tunnels AND backbone** | **br1 withdraws after 60 s** | Zero reachable AS peers → the isolation guard disables br1's anchor. The other BRs keep announcing and traffic moves to them fast because they're healthy. |
| **br1's eBGP to Vultr drops** | br1's announcement gone (session down) | The BGP default is withdrawn → br1 stops offering a default over iBGP → the ERs shift egress to another BR. The distance-250 DHCP default keeps br1 manageable but is never advertised. A remote site just stops seeing a default from br1 (`default-guard` sets `default-originate=never` on the downstream sessions) and egresses via another BR through its own tunnel. Not over the backbone, since it has a tunnel to every BR. **Traffic engineering doesn't change this.** `te.local_pref` picks between defaults that exist. With br1's gone br2's is the only path whatever its value, and the DFZ converges on br2's prepended but now only announcement. Preference comes back when br1 does. Nothing has to fail over. |
| **fwa loses its session to one ER** | Announced | er1 loses the VIP `/32` but er2 still holds it on its own session. er1 relearns it from er2 over the interconnect (er→er permits VIP more-specifics). Inbound shifts to er2 and the `/25` never withdraws. Egress just drops er1 from the firewall's ECMP set. |
| **fwa dies while fwb is alive** (both claim the same VIP) | Announced | The ERs ECMP that VIP across both firewalls, so **half its inbound traffic is black-holed until fwa's sessions drop**. That's detection time and nothing else: **~180 s** on the BGP hold time or **~900 ms** if fwa is flagged for BFD ([ospf.md](ospf.md#bfd-toward-the-customer-firewalls)). Then the VIP resolves to fwb alone and traffic is whole again. This row is why customer BFD exists. |
| **fwa dies entirely (or every firewall does)** | Announced through a short outage. Withdraws only if it stays down | Every VIP session drops → both ERs' `home-anchor-guard` disables the `home-anchor` → the `/25` leaves iBGP → the BRs fall back to their `/24` blackhole (home traffic dropped) but keep announcing. Their own `anchor-guard` only pulls the `/24` after the 10-min no-customer timer, so a brief firewall outage is invisible to the DFZ. Same as a home blip. The guard keys off *route presence* and only starts counting once the sessions drop. Again 180 s, or sub-second with BFD. |
| **A remote site loses one BR** (tunnel, or that BR entirely) | Announced | Only that site's path selection moves. It has a tunnel to *every* BR at equal OSPF cost, so the surviving tunnels carry it. No primary/backup to fail over between. BFD tears the dead adjacency in ~1.2 s. |
| **A remote site loses its WAN** | Announced | Every tunnel from that site drops. Its `/29` leaves iBGP (the connected route is the origination gate) and the rest of the AS stops attracting traffic for it. Home is untouched and the BRs keep announcing because home is still a live customer. The site is dark until its ISP is back. No second uplink. That's the accepted trade for one box per site. |
| **wan1 CPE dies** | Announced | All `*-wan1` tunnels drop. Only the cost-100 `*-wan2` paths remain so both directions move to wan2. The `/24` is untouched because WAN choice is only OSPF cost. A `te.local_pref` preference for a BR survives too: the WAN moved, the border router didn't. The two axes are independent. See [traffic-engineering.md](traffic-engineering.md). |
| **All BRs isolated from home and each other** | **All withdraw (60 s)** | Correct. Nobody can deliver so the isolation guard pulls every anchor. |

### In `origination.mode: home`

The table above is `anchor` mode. [Home mode](origination.md#home-mode) changes the customer signal
to "the home `/25` reaches this BR over its *own* ER tunnels" with a 60 s timer. These rows change.
Every other row stays the same.

| Event | /24 in the DFZ | What happens and why |
|---|---|---|
| **Home down > 60 s** (any number of sites alive) | **All BRs withdraw (60 s)** | No BR has the `/25` over its own tunnels. Sites don't count in home mode. That's the trade this mode makes. |
| **br1 loses all home tunnels; backbone OK** | **br1 withdraws after 60 s** | The `/25` still arrives over iBGP but now resolves via `wg-br2`, and home mode doesn't count that. br2 keeps announcing. This row is the drain lever: disable `wg-br1-*` on er1 and er2. |
| **br1's WAN can reach br2 but not home** (provider-side trouble) | **br1 withdraws after 60 s** | Same mechanism as the row above. Anchor mode would keep announcing and detour through the backbone. |
| **One ER's tunnels to br1 drop, the other's are up** | Announced | er1's loopback resolves via `wg-er2-wan*` and the interconnect. Still one of br1's own home tunnels, so it counts. |
| **wan1 CPE dies** | Announced | The `/25` moves to the `*-wan2` tunnels. Also br1's own home tunnels. |

## Reading the pattern

Three invariants hold across the anchor-mode table. Home mode gives up the first two on purpose.

1. **The `/24` moves only when the AS really can't deliver. Never on a WAN or link change.** WAN
   failover, one tunnel dropping, a BR losing its upstream: none of these touch the aggregate.
   OSPF re-routing ([ospf.md](ospf.md)) and iBGP next-hop re-resolution ([ibgp.md](ibgp.md))
   absorb them *underneath* a stable origination.
2. **"Deliver" means to *any* customer anywhere in the AS.** That's why a lone remote site holds
   the prefix up while home is dark, and it's what makes the no-customer guard safe.
3. **Withdrawal is slow (10 min / 60 s). Re-origination is instant.** Hysteresis keeps a flapping
   link from turning into a global prefix flap.

## What to alert on

`anchor-guard` handles the two automatic failure modes. Monitoring is for *quiet degradation*:
one failure away from an outage but not visible yet.

- **Any `anchor-guard` log line.** `WITHDRAWING` and `RE-ORIGINATING` should both be rare and loud.
- **One BR missing the iBGP `/25` while the others have it.** Per the table this can't happen with
  the backbone up. So the backbone (or its OSPF adjacency) is broken and you're one failure from a
  real outage.
- **OSPF adjacency count per BR.** Should be **7** (2 ER-wan1 + 2 ER-wan2 + 3 backbone). Fewer means
  a tunnel is down.
- **BFD sessions per BR** (once armed). Should be **14**, one per family per adjacency, all `up`.
  A BFD session *down* while its OSPF adjacency is *up* means one end has BFD and the other
  doesn't. A half-finished rollout and a flap waiting to happen. See
  [ospf.md](ospf.md#bfd--the-same-signal-three-orders-of-magnitude-faster).
- **BFD sessions per ER toward the firewalls** (once armed). **Two per flagged firewall**, v4 and
  v6, both `up`. This build doesn't write the far end, so a missing session is as likely a
  firewall change as a fault. While it's down that firewall's VIPs are back on the 3-minute hold
  time. Nothing looks broken. Failover is just slow again.
- **The anchor's `disabled` flag.** Should be `no` basically always.
- **`/routing/bgp/advertisements` toward each upstream.** The `/24` should be there.

Full monitoring notes and reasoning: [AD-LOG.md §11](../AD-LOG.md).
