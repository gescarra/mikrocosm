# Layer 3 — Prefix origination and the anchor

How `203.0.113.0/24` gets announced, why it **stays** announced when home goes dark and how it gets
*withdrawn* in the one case where staying up would be wrong. If you read one doc, read this one.

## The problem it solves

The `/24` used to be originated from the **home** edge routers. So a home power cut, an ISP blip or
a maintenance window **withdrew the prefix from the global table**. Every time. Remote sites hanging
off a datacenter went dark with home. Every peering was hostage to a residential ISP.

Origination lives on the **border routers** now. The trade:

- **Before:** home down → prefix withdrawn globally. The AS goes *invisible*.
- **After:** home down → prefix **stays announced** and traffic for home is dropped *at the BRs*. The
  AS becomes a *black hole* for that space.

An end user gets a timeout either way. But for the global table a black hole is much quieter than a
prefix that comes and goes on every home hiccup. The cost: a safety property that used to be
*emergent* (home dies, origination dies with it) is now *scripted*. That's what `anchor-guard` is
for.

## The three mechanisms

Three interlocking parts.

### 1. The origination anchor (on every BR)

Every BR holds `203.0.113.0/24` as a **`blackhole` route at `distance=254`** and originates the
prefix from it via `output.network`:

```routeros
/ip/firewall/address-list add list=my-aggregate address=203.0.113.0/24
/ip/route add dst-address=203.0.113.0/24 blackhole distance=254 comment="anchor"
```

Two properties make it work:

- **`distance=254` loses to everything.** Any real route to in-block space beats the anchor: an ER's
  `/25`, a remote site's `/29`, a more-specific from iBGP. The blackhole only *catches* in-block
  traffic nothing else claims. A floor, not a preference.
- **`output.network` originates the `/24` only if a matching route is in the table.** The anchor
  *is* that route. So enabling or disabling the anchor is the origination switch, and that's what
  `anchor-guard` toggles.

`output.network-blackhole=no` is set on the eBGP template. Leave it at `yes` and RouterOS creates
its *own* blackhole to satisfy `output.network`. Toggling the anchor then does nothing and
**`anchor-guard` becomes a silent no-op that logs `WITHDRAWING` while the BR keeps announcing.**
Verify this before you arm the guard. Nothing else comes close in importance (see
[below](#proving-the-anchor-gates-origination)).

### 2. The ERs advertise their attached block (the `/25`)

The ERs put `203.0.113.0/25` into iBGP with next-hop-self, gated by a **blackhole `home-anchor`**.
Same mechanism as the BR's `/24` anchor, one level down:

```routeros
add dst-address=203.0.113.0/25 blackhole distance=254 comment="home-anchor"
```

`output.network=advertise` sends the `/25` only while a matching route exists. This anchor is that
route, so toggling it is the origination switch. `home-anchor-guard` does the toggling (below).
`output.network-blackhole=no` on the iBGP template is mandatory for the same reason as on the BRs.
At `yes` RouterOS invents its own blackhole and the guard becomes a no-op.

The anchor does double duty. Customer VIPs arrive as **eBGP `/32`s at distance 20** and always win
for claimed IPs on longest-prefix-match. The `/25` blackhole only catches **unclaimed** home space
and drops it at hdc so it can't loop.

A `/25` is **longer than a `/24`**, so the ERs' `/25` beats every BR's `/24` blackhole whenever it
exists. When the last live customer VIP withdraws, `home-anchor-guard` disables the anchor → the
`/25` leaves iBGP → the BRs quietly fall back to their blackhole. **The `/24` upstream never moves.**
That's the whole trick. The aggregate is stable at the border while the specific comes and goes at
home.

The ERs also hold a `203.0.113.0/24` blackhole at `distance=254`. On the ERs it's **only a loop
guard**. The output filter rejects it so it's never advertised. It just stops an in-block packet
with no specific route from looping.

### 3. The BR↔BR backbone keeps iBGP alive

A BR that lost *all* its home tunnels can still reach the ER loopbacks **through a sibling BR over
the backbone** (OSPF resolves `er1-lo` via `br2`). Its iBGP sessions survive, it keeps the `/25` and
it *forwards* home traffic one extra datacenter hop instead of black-holing it. The remote-site
design needs the same backbone. Without it a BR cut off from home would have no live customer route
and fall to its blackhole for no reason.

## `anchor-guard` — two signals, two timers

The anchor makes origination *unconditional*. `anchor-guard` decides when to make it conditional
again. When the black hole does more harm than good and the BR should **withdraw** instead of
swallowing traffic nothing can deliver.

It watches two separate questions because they have **different right answers**:

| Signal | Question | Withdraw after | Why that timer |
|---|---|---|---|
| **Isolation** | Can I reach *any* router in AS64500? (via OSPF-fed routes to peer loopbacks) | **60 s** | I'm an island. My healthy siblings can take this traffic *now*. Move fast. |
| **No customer** | Do I have an active route to *any* customer prefix? (the `/25`, or any remote-site `/29`) | **10 min** | Nobody in the whole AS can deliver. That's a DFZ-level event. Go slow. |

The script counts consecutive failures on a 10-second scheduler. Isolation fires at 6 misses in a
row (≈60s) and no-customer at 60 (≈10min). To pull it sets the anchor route `disabled=yes` and
origination stops. When either signal recovers it re-enables **immediately**.

Two design points hold the whole thing up:

- **The customer signal is "*any* customer prefix". Not "the ER's `/25`".** Triggering on losing the
  `/25` would bring back the exact home dependency this design removes. An 11-minute home outage
  would withdraw the prefix from every BR and kill every remote site. Counting *any* customer prefix
  is what lets a live remote site hold the prefix up while home is dark.
- **Hysteresis: slow to withdraw, instant to re-originate.** Without it one flapping OSPF adjacency
  turns into the upstream prefix flap the design exists to prevent.

### `home-anchor-guard` — the ER's own, simpler guard

The ERs run a guard too but it asks one question: **is any customer prefix a live eBGP route?** A
firewall proves it's alive by advertising into the space it was granted, and the ER installs that as
an active route. For an enumerated `allowed_vips` grant that's an exact `/32`. For a `delegations`
grant it's *any* active route inside the delegated block. Which more-specifics the firewall picks is
its own business and the guard doesn't care. While ≥1 grant is live the guard keeps `home-anchor`
enabled and the `/25` originated. When the last one withdraws it disables the anchor, and the BRs'
`anchor-guard` stops seeing the `/25`. Same shape and same safe default as the BR guard: ships
**enabled** with the scheduler commented out. Arm it only after you prove it (below).

This replaces the old `check-gateway=ping`. A ping proves a box answers ICMP. A live BGP route proves
it's forwarding and healthy enough to hold a session. **Real health, not just reachability.** That's
the point of moving home reachability onto BGP. There's **no hysteresis on the ER guard** on purpose.
The BRs' 10-minute no-customer timer already absorbs short VIP flaps so a brief firewall outage never
reaches the DFZ (see [failure-modes.md](failure-modes.md)).

## Home mode

`origination.mode` in `topology.yml` picks what `anchor-guard` counts as "a customer I can deliver
to". Everything above is **`anchor`**, the default. **`home`** keeps the same anchor, the same
`output.network`, the same script and the same instant re-origination. It changes one signal:

| | `anchor` | `home` |
|---|---|---|
| Customer signal | *any* active customer prefix (the `/25`, any site `/29`) however it's reached | the home `/25` (and `/48`) whose **resolved next hop leaves through one of this BR's own ER tunnels** |
| A `/25` reached over the backbone | counts | **doesn't count** |
| Withdraw after | 10 min | 60 s |
| A live remote site holds the `/24` up | yes | no |

The check is on `immediate-gw`, the next hop the `/25` actually resolves to. With br1's tunnels to
the ERs up, the ERs' loopbacks resolve over them (`…%wg-er1-wan1`). With them down mechanism 3 kicks
in. The iBGP sessions survive over the backbone and the `/25` is still there. But it now resolves
`…%wg-br2` and home mode doesn't count that.

**Why you'd want it: a drain lever you pull from home.** In anchor mode disabling the ERs' tunnels to
a BR does nothing to its announcement, by design (the backbone row in
[failure-modes.md](failure-modes.md)). If a provider is mangling *our* traffic while its BGP session
stays up, that BR keeps attracting traffic. In home mode:

```routeros
# on er1 AND er2 -- drain br1
/interface/wireguard/disable [find name~"^wg-br1-"]
# ~60 s later br1 stops announcing; br2 never moved.
/interface/wireguard/enable  [find name~"^wg-br1-"]   # br1 re-originates on the next tick
```

The same signal withdraws a BR by itself when its WAN can't reach home anymore. That covers the
provider-side failure anchor mode rides out by detouring through the backbone.

**What it costs.** Three things and you're signing up for all of them:

- **A home outage longer than 60 s withdraws the `/24` from every BR.** That's the "Before" column at
  the top of this page. The AS goes invisible instead of becoming a black hole.
- **Remote sites don't hold the prefix up anymore.** With `sites: []` today that's free. It stops
  being free the day the first site goes live.
- **The lever is device state on the ERs.** A `reset-configuration` redeploy of an ER re-enables its
  tunnels and un-drains the BR. Re-disable them after any ER deploy during a drain.

Unlike the [community idea below](#why-not-just-signal-stop-announcing-with-a-community), home mode
fails *closed*. If the control path dies the BR withdraws. It doesn't un-suppress itself. And it
never touches the anchor route directly so it can't fight `anchor-guard`. It *is* `anchor-guard`,
reading a different signal.

**Neither mode does anything until the guard is armed** (`origination.arm_guard: true`). Flipping
the mode alone changes a script no scheduler runs. Home mode adds a second proof before arming,
rendered next to the scheduler line in each `br*.rsc`. With the tunnels up,
`immediate-gw~"%wg-er"` must find the `/25`. With the ERs' tunnels to that BR disabled it must find
nothing while the `/25` is still present. If the first check comes back empty, the property or its
format isn't what this fleet assumes. Arm in that state and the `/24` disappears from every BR 60 s
later.

## Proving the anchor gates origination

The generator emits the script but **leaves the scheduler commented out on purpose**
(`origination.arm_guard: false`). Before arming, prove the anchor route really controls origination.
If it doesn't, every guarantee in [failure-modes.md](failure-modes.md) is fiction:

```routeros
/ip/route/disable [find comment="anchor"]
/routing/bgp/advertisements/print peer=ebgp-upstream     # the /24 must be GONE
/ip/route/enable  [find comment="anchor"]
/routing/bgp/advertisements/print peer=ebgp-upstream     # the /24 must be BACK
```

`/24` still advertised with the anchor disabled? `output.network-blackhole` didn't take and the
guard is a no-op. Fix that first. Only then set `origination.arm_guard: true` and redeploy.

The **ERs** need the same proof for the `/25`, against `comment="home-anchor"` and any iBGP peer:

```routeros
/ip/route/disable [find comment="home-anchor"]
/routing/bgp/advertisements/print peer=ibgp-br1     # the /25 must be GONE
/ip/route/enable  [find comment="home-anchor"]
/routing/bgp/advertisements/print peer=ibgp-br1     # the /25 must be BACK
```

## Why not just signal "stop announcing" with a community?

The instinct keeps coming back: tag a route from home with "don't announce from br1" and pull an
announcement without logging into a BR. **It can't work.** The reasons are structural (full detail in
[AD-LOG.md §9.2](../AD-LOG.md)):

1. Communities ride on prefixes. But the `/24` is originated *locally* on each BR and never travels,
   so there's no prefix to carry the tag.
2. BGP best-path prefers locally originated routes. A tagged `/24` over iBGP would never become the
   route the output filter sees.
3. It **fails open**. Home goes down → the tag vanishes → the BR you suppressed un-suppresses itself.
   A kill switch that disarms when your control plane dies is worse than none.

Suppressing a BR's origination is **device state**, not route policy. The right kill switch is to
disable the eBGP session (`ssh <br-loopback> '/routing/bgp/connection set [find name=ebgp-...]
disabled=yes'`). Persistent, survives reboots and doesn't fight `anchor-guard`, which only ever
touches the anchor *route*. Better still, manage it in Ansible + git. See [AD-LOG.md §10](../AD-LOG.md).

---

**See it in action:** [failure-modes.md](failure-modes.md) walks every failure through these three
mechanisms end to end.
