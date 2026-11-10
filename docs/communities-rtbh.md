# BGP communities and RTBH

There are **two completely separate community namespaces** here. Mixing them up is a classic way
to break things quietly. Get this straight first and the rest follows.

## Two namespaces

**1. Communities you *send to an upstream* are defined by *them*.** You use whatever they specify in
whatever format they specify. They mean nothing inside your AS.

| Community | Upstream | Purpose |
|---|---|---|
| `65500:10000` | **HostHatch** | **Mandatory.** Without it HostHatch's DDoS-scrubbing platform doesn't propagate your announcement *at all*. Set only on the HostHatch eBGP chain. Means nothing to Vultr. |

**2. Communities *you define for your own routers to act on*** are internal route policy. With one
hard constraint:

> A standard BGP community is 16 bits of ASN + 16 bits of value. **AS64500 needs 32 bits. It
> doesn't fit.**

So every internal tag is a **large community** (RFC 8092), `64500:<function>:<value>`, exposed in
RouterOS as `bgp-large-communities`:

| Large community | Meaning | Acted on by |
|---|---|---|
| `64500:1:666` | **RTBH**: blackhole this `/32` at every upstream | BRs → translate to each upstream's blackhole community |
| `64500:1:1xxx` | Origin site tag (1001 hdc, 1002 ord1, 1003 ord2) | nobody. Informational, for troubleshooting |
| `64500:2:1` / `:2:2` / `:2:3` | Prepend ×1 / ×2 / ×3 to all upstreams | BRs. A per-prefix **override**, see below |
| `64500:3:<asn>` | Do **not** announce to upstream ASN `<asn>` | BRs |

The two never collide because **internal large communities are stripped on eBGP egress** and the
upstream's standard communities get set at that same moment. Everything in the internal table is
real *route policy*, a property of a prefix you're actually advertising. That's what communities
are for. (Why they *can't* work as a remote kill switch:
[origination.md](origination.md#why-not-just-signal-stop-announcing-with-a-community) and
[AD-LOG.md §9.2](../AD-LOG.md).)

## The eBGP output filter chain

Each BR's eBGP output is a per-upstream chain that jumps to a shared tail.

**Per-upstream head** (`ebgp-out-upstream`, different on each BR):
- HostHatch only: `set bgp-communities 65500:10000` first. Before the jump, so it covers the
  aggregate and RTBH `/32`s alike.
- The static `te.prepend` if this BR has one, matched on the **aggregate only**.
- Translate internal prepend tags (`64500:2:*`) to `bgp-path-prepend`.
- Honour `64500:3:<asn>` by rejecting for that upstream.
- `jump ebgp-out`.

### The `2:N` tags are an override, not the only prepend

They were the *only* prepend mechanism until `te.prepend` showed up. Reading them that way now
misleads you twice.

**They can never touch the aggregate.** The `/24` is originated locally from the anchor
([origination.md](origination.md)) and carries no communities, so no `2:N` rule ever matches it.
Steering ingress for the whole AS is `te.prepend`'s job
([traffic-engineering.md](traffic-engineering.md)). These tags are a per-prefix tool for something
you're actually carrying in BGP.

**Where both apply the community wins.** `set bgp-path-prepend` assigns, it doesn't accumulate. The
static rule is emitted *above* the `2:N` ladder so the ladder runs the last `set`. On purpose. A
runtime tag can out-vote `topology.yml` on one prefix without a regenerate and redeploy.

**Shared tail** (`ebgp-out`, same everywhere):
- An RTBH `/32` carrying `64500:1:666`: strip the internal large community, set the upstream's
  blackhole community (`65535:666,no-export`), accept.
- The `203.0.113.0/24` aggregate: strip internal large communities, accept.
- **`reject`**. Terminal. This stops an untagged more-specific (a fat-fingered static, a leaked
  `/32`) from ever walking upstream. The chain **must** end here.

### The HostHatch clobber trap

`ebgp-out`'s RTBH rule does `set bgp-communities 65535:666,no-export`. That's a **replace, not an
append.** On the HostHatch path it can overwrite the mandatory `65500:10000`, so an RTBH
announcement might never clear their scrubber. RTBH quietly failing on the one provider whose DDoS
platform you're trying to reach. If it clobbers on your build, set both in one action:
`set bgp-communities 65500:10000,65535:666,no-export`. Check on a live session.

## RTBH — remote-triggered black-holing

With a `/24` and several upstreams you'll eventually want to null one attacked host from one
place. RTBH is script-free and BGP-native. The right tool. The **whole operator workflow** is three
lines on an ER:

```routeros
/ip/route
add dst-address=203.0.113.130/32 blackhole comment="rtbh"
/ip/firewall/address-list
add list=advertise address=203.0.113.130 comment="rtbh"
add list=rtbh    address=203.0.113.130 comment="rtbh"
```

You need all three, and **the `rtbh` list entry is the tag**:

- `advertise` drives `output.network` so the `/32` gets originated;
- the blackhole route makes it active;
- the `rtbh` list is what the ER's `ibgp-out` filter checks before attaching `64500:1:666`.

To undo, delete all three.

### The IPv6 form

Same shape, different menus and a `/128` instead of a `/32`:

```routeros
/ipv6/route
add dst-address=2001:DB8:1::130/128 blackhole comment="rtbh"
/ipv6/firewall/address-list
add list=advertise6 address=2001:DB8:1::130 comment="rtbh"
add list=rtbh6      address=2001:DB8:1::130 comment="rtbh"
```

`advertise6` already exists. The ER template creates it holding the customer `/48`. **`rtbh6`
doesn't exist until you create it**, same as `rtbh` on the v4 side. The routing filter just never
matches until the list has an entry, so forgetting still fails closed.

The case for an explicit tag is *stronger* in v6. In v4 "infer RTBH from prefix length" at least
sounded plausible because a `/32` is a host route. In v6 a `/128` is a perfectly ordinary customer
service address. `fwb` is granted one in `topology.yml` right now. Length tells you nothing.
Membership of `rtbh6` is the only thing that means "null this".

### Why RTBH is explicit now

The filter used to tag *any* `/32` out of `203.0.113.0/24` as RTBH and infer intent from prefix
length. Safe only while nothing else originated a `/32`. Not anymore. Customer firewalls now claim
VIP `/32`s out of `203.0.113.0/25` over eBGP, and under the old rule **every VIP claim quietly
became a blackhole nulled at every upstream**. The exact opposite of what the customer asked for.
No error anywhere.

So RTBH is **explicit** now. A `/32` is a blackhole request only when an operator put it on the
`rtbh` list. Forget that entry and the `/32` is an ordinary more-specific, which the iBGP output
filter denies to the BRs anyway. It goes nowhere. **Forgetting fails closed.** Right direction.

## Before you rely on RTBH

RTBH depends on things the config can't check for you. Verify each per upstream ([AD-LOG.md §9.4](../AD-LOG.md)):

- **`65535:666` is the well-known BLACKHOLE community (RFC 7999). Confirm each provider honours
  it.** Some want their own.
- **Confirm the upstream accepts a `/32` from you at all.** Providers normally filter you to your
  registered prefix at max-length 24. Customer RTBH is a deliberate exception on a separate relaxed
  filter.
- **Your ROA has maxLength 24, so an RTBH `/32` is RPKI-invalid.** Most providers exempt blackhole
  announcements since they carry NO_EXPORT and never reach the DFZ. Confirm it. But **don't widen
  your ROA to /32** to "fix" it. That opens you to hijack-by-more-specific, a far worse problem.
- **If an upstream ignores the community the traffic still arrives.** It reaches your BR, crosses
  the tunnel and dies on the ER's blackhole *after* eating your home bandwidth. The exact thing
  RTBH is supposed to prevent. Checking provider support beats any amount of config.
