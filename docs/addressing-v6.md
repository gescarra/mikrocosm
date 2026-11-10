# IPv6 addressing — `2001:DB8::/40`

The v4 plan in [addressing.md](addressing.md) carves a single `/24` because that's all there is.
This one carves `2001:DB8::/40`, 256 `/48`s, and the rule is the opposite: **stop conserving.**
Every block is nibble-aligned, sized for legibility over density and derived from the same index
arithmetic that already drives `topology.yml`.

Hand-picking a `/127`? Same thing went wrong as it would in v4.

## The top-level carve

| Block | Use |
|---|---|
| `2001:DB8:00::/48` | Infrastructure: loopbacks, P2P links, transit |
| `2001:DB8:01::/48` | `hdc`, the home site (the `203.0.113.0/25` analog) |
| `2001:DB8:02::/48` | `site1` (first remote site) |
| `2001:DB8:03::/48` | `site2` |
| `2001:DB8:04::/48` … `0F::/48` | Remaining sites, allocated sequentially |
| `2001:DB8:10::/44` … `FB::/48` | Unallocated growth |
| `2001:DB8:FC::/46` | **AWS BYOIP**: four `/48`s, reserved |

Infrastructure at `00`, sites counting up from `01` and AWS pinned at the ceiling so growth from the
bottom can never hit it. Sites are allocated **in order and never reused**. A decommissioned site's
`/48` stays burned because stale route objects and third-party filters outlive your topology.

### Why a `/48` per site

RFC 6177 says a `/48` per site. Not worth being clever about. But the payoff here is specific to
*this* design. In v4 home holds a `/25`, **half the AS**. That asymmetry is why
[origination.md](origination.md) keeps having to explain the `/25` is special. In v6 `hdc` holds one
`/48` out of 256, same as every remote site will.

So `anchor-guard`'s "*any* customer prefix" test ([origination.md:106](origination.md:106)) becomes
truly uniform. No privileged home prefix, just a set of site `/48`s and any one of them holds the
aggregate up. The special case disappears instead of being carefully handled.

### The allocation is not the announcement

ARIN allocated `2001:DB8::/40`. The BRs originate **`2001:DB8::/42`**, the first 64 `/48`s. No v4
counterpart (there we announce the whole `/24`), so `topology.yml` carries both. `prefix_v6` is the
allocation and `aggregate_v6` is what we announce.

The reason isn't the obvious one. Announcing the whole `/40` works *externally* because AWS's `/48`
is a more-specific and wins for the outside world. The problem is **internal**. Per
[origination.md](origination.md) each BR holds the announced aggregate as a `blackhole` at
`distance=254`. If that anchor covered `FC::/46`, traffic from inside AS64500 to our own AWS BYOIP
space would hit the blackhole and get dropped. Meanwhile the rest of the internet reaches it fine
via AWS. A split-brain you can only see from inside.

Announce only what we route and the AWS range drops out of our table. In-AS traffic falls through to
the default and reaches AWS like any other destination. No hole-punching route needed.

**One prefix, not several.** Carving the `/40` around `FC::/46` would take seven prefixes
(`/42`+`/42`+`/42`+`/43`+`/44`+`/45`+`/46`). Deaggregation for nothing. The `/42` is one DFZ entry,
same as the `/40` was, and `00–3F` is infra + hdc + 62 sites of headroom. Everything from `40::` up
is unannounced. Not lost though. A future block can get its own announcement.

`generate.py` refuses to render if `aggregate_v6` overlaps `aws_byoip_v6` or falls outside
`prefix_v6`. It also refuses if any block in `blocks_v6` sits outside the announced aggregate. That
last one pays off years from now. It catches someone allocating a site at `0x40` and quietly
addressing hosts the world has no route to.

### The AWS reservation is a contiguous `/46` on purpose

AWS BYOIP needs ROAs authorising **AS14618 and AS16509** (both Amazon) to originate the prefix. Not
AS64500. So this block is the one place inside the `/40` where the origin AS isn't ours. Keeping it
contiguous makes that exception *one* range you can state in a sentence, filter on and reason about.
Not four scattered `/48`s you have to remember one by one.

**Get those ROAs right before AWS starts advertising.** We kept the `/40` ROA on purpose, so this
range is already *covered* by a ROA with origin AS64500. A missing, expired or wrong-ASN AWS ROA
doesn't leave the `/48`s Unknown. It makes them **Invalid**, and validating networks drop Invalid
outright. Right trade (the `/40` ROA protects the unannounced remainder from hijack) but there's no
soft-failure mode here.

AWS advertises at `/48` minimum so all four can be onboarded independently. Reserve now, onboard one
at a time.

## Inside the infrastructure `/48`

One `/60` per class. A `/60` is sixteen `/64`s, way more than any class will use. That's the point.
The fourth hextet's leading nibble becomes a category label you can read at a glance.

| Block | Use | v4 counterpart |
|---|---|---|
| `2001:DB8:0:0000::/60` | Loopbacks (`/128`s) | `.240/28` |
| `2001:DB8:0:0010::/60` | BR↔BR backbone `/127`s | `.160/28` |
| `2001:DB8:0:0020::/60` | Remote-site tunnel `/127`s | `.176/28` |
| `2001:DB8:0:0030::/60` | BR↔ER tunnel `/127`s | `.192/27` |
| `2001:DB8:0:0040::/60` | ER interconnect + firewall transit | `.224/28` |

Point-to-point links are `/127` per RFC 6164. The exact `/31` analog and for the same reason: a `/64`
on a P2P link is a ping-pong and neighbour-cache-exhaustion target.

### Loopbacks

| Address | Router |
|---|---|
| `2001:DB8:0::b1` | `br1.ord1` |
| `2001:DB8:0::b2` | `br2.ord2` |
| `2001:DB8:0::b3` / `::b4` | br3 / br4 (future) |
| `2001:DB8:0::51` | `sr1.<site1>`, remote-site router, index 1 |
| `2001:DB8:0::52` | `sr1.<site2>` |
| `2001:DB8:0::e1` | `er1.hdc` |
| `2001:DB8:0::e2` | `er2.hdc` |

`b` = border, `e` = edge, `5` = **s**ite (hex has no `s` and `5` is the only nibble that reads as
one), digit = the router's `index`. Still pure index arithmetic for the generator but hex lets it
spell something. A `traceroute` through the AS names its own hops before DNS even resolves. That's
the goal [addressing.md](addressing.md#naming-convention) states and v4 can only approximate with
`.241`/`.249`.

Like v4 the loopback is the canonical router address. OSPFv3 router-id, iBGP peering address and
what the bare router name resolves to on `AAAA`.

### P2P link derivation

The offsets are **the v4 formulas with the base removed**. Same arithmetic, new block. A `/127` uses
two addresses just like a `/31`.

**BR↔ER tunnels**: `off = (br.index - 1) * 8 + (er.index - 1) * 4 + (wan - 1) * 2` out of
`2001:DB8:0:30::`. The BR takes the even address and the ER the odd one:

| Tunnel | BR side | ER side |
|---|---|---|
| br1↔er1 wan1 | `2001:DB8:0:30::0/127` | `2001:DB8:0:30::1/127` |
| br1↔er1 wan2 | `2001:DB8:0:30::2/127` | `2001:DB8:0:30::3/127` |
| br1↔er2 wan1 | `2001:DB8:0:30::4/127` | `2001:DB8:0:30::5/127` |
| br2↔er1 wan1 | `2001:DB8:0:30::8/127` | `2001:DB8:0:30::9/127` |

Compare [generate.py:159](../generate.py:159). Same expression once `192` becomes the block base. On
purpose. The v6 build path is the v4 build path with a different `ip()`.

**BR↔BR backbone**: link `i` (in `itertools.combinations` order, as today) takes
`2001:DB8:0:10::(2i)/127`. `br1↔br2` is `::0`/`::1`.

**Remote-site tunnels**: same shape out of `2001:DB8:0:20::`.
`off = (site.index - 1) * 2 * SITE_BR_SLOTS + (br.index - 1) * 2` with the BR on the even address.
`site1↔br1` is `::0`/`::1`, `site1↔br2` is `::2`/`::3`, `site2↔br1` is `::4`/`::5`.

The v4 side of that formula is the one place in this repo where **v6 isn't the tight family**.
`blocks.site_p2p` is a `/28`: eight `/31`s total, four sites at two BRs. `2001:DB8:0:20::/60` could
address every site tunnel this AS will ever have. If the v4 block ever blocks a third BR, running
the site tunnels v6-only is a real option and the validation error says so.

**Site LANs**: a site's `/48` is `2001:DB8:(1 + index)::/48` (so `site1` = `02::/48`, matching the
table up top). Its LAN is the first `/64` of that and the router holds `::1` with
**`advertise=yes`**. The only Router Advertisement in the whole fleet. Inside devices SLAAC out of it
and learn the site router as their gateway. The v6 version of handing them the `/29`'s first address
in v4.

What the site *originates* is the whole `/48`, gated on a distance-254 blackhole anchor (the ERs'
`home-anchor` pattern). Not the connected `/64`. On purpose: a second LAN at a site needs no
re-render anywhere else. But it's a real asymmetry with v4, where the delegation *is* the LAN and the
connected route gates origination. In v6 a site whose LAN is down keeps announcing its `/48` and
blackholes it locally. Same drop, different place. It only affects the "is any customer being
delivered" signal in `anchor-guard`, which isn't armed yet.

### Home local links

| Address | Use |
|---|---|
| `2001:DB8:0:40::0/127` | ER↔ER interconnect: er1 = `::0`, er2 = `::1` |
| `2001:DB8:0:41::/64` | Firewall transit segment |
| `2001:DB8:0:41::1` | er1 transit address |
| `2001:DB8:0:41::2` | er2 transit address |
| `2001:DB8:0:41::10` | `fwa` peer address |
| `2001:DB8:0:41::11` | `fwb` peer address |

The transit segment is a real `/64` because it's a shared L2 broadcast domain with several firewalls
on it. Not a P2P link. It lives in the **infrastructure** `/48`, not the `hdc` `/48`. Mirrors v4,
where `local_links` comes from the `/24` and not the customer `/25`. Keeps the customer block cleanly
delegable. Nothing the ERs need for their own plumbing sits in space a firewall might carve up.

## Inside the `hdc` `/48`

| Block | Use |
|---|---|
| `2001:DB8:1:0000::/56` | Service / VIP `/128`s |
| `2001:DB8:1:0100::/56` | `fwa` delegation, `max_len: 64` |
| `2001:DB8:1:0200::/56` | `fwb` delegation, `max_len: 64` |
| `2001:DB8:1:0300::/56` … | Future firewalls / delegations |

A `/56` per firewall is 256 `/64` LANs. The standard downstream-site delegation, and enough that no
firewall ever comes back asking for a second block.

`max_len: 64` instead of v4's `max_len: 32` because **a v6 LAN is a `/64`**. SLAAC and most
autoconfiguration break on anything longer. A firewall advertising a `/128` service address is
advertising a host route, and that's what the VIP `/56` is for. So the delegation ceiling and the VIP
block cover the two legit cases and nothing else.

Maps straight onto the existing `delegations:` schema in [topology.yml:153](../topology.yml:153). Same
`prefix` + `max_len` pair, same compilation to a prefix and an accepted `dst-len` range. The firewall
grant model doesn't change at all. Only the numbers.

## Origination — what carries over unchanged

The whole [origination.md](origination.md) mechanism carries over untouched:

- The **BRs originate `2001:DB8::/42`**, the *announced aggregate* and not the whole allocation (see
  [above](#the-allocation-is-not-the-announcement)), from a `blackhole` anchor at `distance=254`
  gated by `output.network`. Same anchor, same `output.network-blackhole=no` requirement, same proof
  before arming the scheduler.
- The **ERs advertise `2001:DB8:1::/48`** into iBGP with next-hop-self, gated by a `home-anchor`.
- A `/48` beats a `/40` on longest-prefix-match just like a `/25` beats a `/24`, so fallback is
  identical. When the last firewall grant withdraws the `/48` leaves iBGP and the BRs fall back to
  their blackhole. **The `/40` upstream never moves.**

`anchor-guard`'s two signals and two timers don't change. Its customer-prefix test just gains the
site `/48`s next to the v4 prefixes.

A `/40` sits comfortably inside every sane filter in the ARIN `2602::/20` region, where `/48` is the
usual floor. The aggregate will propagate.

## RPKI — the maxLength decision

Issue **two kinds of ROA and no others**:

| Prefix | Origin AS | maxLength | Why |
|---|---|---|---|
| `2001:DB8::/40` | 64500 | **40** | makes the *unannounced* rest of the `/40` Invalid to hijack |
| `2001:DB8::/42` | 64500 | **42** | makes the actual announcement Valid |
| `2001:DB8:FC::/46` | **14618** | 48 | AWS BYOIP, see below |
| `2001:DB8:FC::/46` | **16509** | 48 | AWS BYOIP, see below |

**AWS needs TWO ROAs, not one.** It advertises BYOIP space from AS14618 or AS16509 depending on the
region. Authorise both or the regions using the other ASN come out Invalid. Two ROAs for one prefix
with different origins is legal and normal. A route is Valid if **any** ROA validates it, so
whichever ASN actually originates is covered.

One `/46` at maxLength 48 per ASN covers all four `/48`s (`FC`, `FD`, `FE`, `FF`). One per region,
filling the reservation exactly. The looser maxLength also authorises the `/46` and both `/47`s from
those origins. A deliberate trade: you can re-split the block later without issuing new ROAs and
waiting on propagation again.

You need both AS64500 ROAs, and the reason is a real foot-gun.

**A `/40` ROA at maxLength 40 makes a `/42` announcement RPKI *Invalid*.** The space is covered by a
ROA but no ROA validates a prefix that long (RFC 6811). Invalid is strictly worse than no ROA at all.
Networks doing origin validation **drop** Invalid routes where they'd have accepted an Unknown one.
So the `/42` needs its own ROA before it's announced.

Keeping the `/40` ROA too isn't redundant. It makes every unannounced `/48` inside the allocation
*Invalid* for anyone else to originate instead of just Unknown. And it doesn't hurt AWS. A route is
Valid if **any** ROA validates it, so an AWS `/48` from AS14618 or AS16509 validates against its own
ROA regardless of the covering `/40` ROA with a different origin.

Tight maxLength is the defence throughout. Each ROA authorises exactly one length, so a hijacker
spoofing our origin still can't announce more-specifics that validate.

Create the AWS ROAs **as you onboard each `/48`**, not up front. A ROA authorising Amazon to
originate space you haven't handed them yet is a standing invitation.

## Reverse DNS

A `/40` is nibble-aligned so ARIN delegates one clean zone:

```
0.0.8.b.d.0.1.0.0.2.ip6.arpa
```

The v4 rules in [addressing.md](addressing.md#dns--examplenet) still hold, and one gets stronger:
**the PTRs that count most are still the provider WAN addresses**, which live in the provider panel.
Dual-stack means each BR now has a v6 WAN address whose PTR is just as out of your hands and just as
worth setting. A v6-sourced traceroute or mail connection shows that address, not anything in your
own zone.

Forward records follow the v4 convention exactly. The bare router name gets an `AAAA` at its
loopback. Interface addresses get `{interface}.{router}.{site}.example.net`. Both families share one
name. Nothing gets a `-v6` suffix.

## Two protocol decisions this plan assumes

Both belong to the topology phase but the addressing above was picked with them in mind.

**The RA setting costs a reboot on every deploy. On every router.** RouterOS doesn't apply
`/ipv6/settings accept-router-advertisements` until a reboot. `reset-configuration` restores the
factory default (`yes-if-forwarding-disabled`) and reboots. `run-after-reset` then sets our value and
nothing reboots afterwards. So the value never takes effect.

It's not just Vultr's `=yes`. The factory default is `yes-if-forwarding-disabled`, so `br2` and both
ERs setting `=no` change it just as much. That's why `ansible/deploy.yml` reboots
**unconditionally** after any applied config and checks for an active `::/0` afterwards on the
`gateway: ra` routers, where the RA is what produces the default.

Without it the failure is quiet. v4 is perfectly healthy and only IPv6 egress is dead.

**Ask the provider which address they peer with. Owning the `/64` isn't the same as choosing.** Both
of ours constrain it differently. HostHatch peers only with `::179`. Vultr only with the address
assigned to the *instance*, an EUI-64 value derived from the NIC MAC that changes if the instance is
rebuilt. Use any address in the `/64` for anything else. But the BGP session has to source from the
one they expect.

Getting it wrong is expensive to diagnose because it fails **silently at the TCP layer**. The SYN is
dropped. No RST, no ICMP unreachable, nothing in the BGP log. The session just never appears. The
tell is `/ipv6/firewall/connection`: the outbound flow sits at `tcp-state=syn-sent` with
`repl-packets=0` forever. And if the provider is also trying to reach you there's an inbound flow to
whichever of your addresses they actually expect. The exact values live in `topology.yml` next to
each BR's `wan_v6` block.

**iBGP: separate sessions over v6 loopbacks** instead of carrying the v6 AFI on the existing v4
sessions. Double the sessions. What it buys: trivial next-hop-self (no RFC 5549 next-hop gymnastics)
and separate failure domains. A v6 policy mistake can't take v4 down with it. The loopback scheme
above gives every router a v6 loopback so these sessions have a canonical endpoint.

**OSPFv3 as a separate instance.** RouterOS 7 runs it next to OSPFv2 with no interaction.
Adjacencies form on link-local addresses so the protocol doesn't **need** the `/127` GUAs on tunnels.
They're there for traceroute legibility and the DNS convention. A real cost (addresses to manage) for
a real benefit (a path through the AS that describes itself). Same trade v4 already makes.

WAN preference stays put: OSPFv3 cost, same values as v2 (`wan1` = 10, `wan2` = 100). Don't express
it in BGP and don't let the two IGPs disagree. A v4 path and a v6 path preferring different WANs make
failures asymmetric and debugging miserable.

---

## Status

Implemented. `prefix_v6` in [`../topology.yml`](../topology.yml) is the master switch. Set it and
IPv6 turns on across the generator and both templates. `generate.py` refuses to render a border
router without a `wan_v6` block instead of quietly producing a v6-less BR.

Everything above is derived, not listed. The P2P offset formulas are the v4 ones with the base
swapped, so addressing arithmetic lives in exactly one place.

**Not done yet.** Each one is a deliberate stop, not an oversight:

- **ROAs.** Nothing is announced until the `/40` ROA exists (maxLength 40, AS64500). Create it before
  the first eBGP v6 session comes up. Not after.
- **The reverse zone.** `reverse_v6_zone_id` is filled in `topology.yml` but the ARIN delegation and
  the PTR push are separate steps.
- **Provider WAN PTRs.** Set in the Vultr and HostHatch panels. These are the addresses the outside
  world sees and they aren't ours to self-manage.
- **`anchor-guard` stays unarmed**, same reason as on v4. With `sites: []` the "any customer prefix"
  generalisation has nothing to generalise over. Dual-stack doesn't change that, and arming it now
  means a long home outage withdraws the aggregate from the DFZ.
