# AS64500 — Architectural Decision Log

**Why the network is built the way it is. Decisions, trade-offs and the RouterOS v7 config that follows from them.**
Prefix: `203.0.113.0/24` · ASN: `64500`

> This records *decisions*: what was chosen, what it beat and the failure that justifies it. It's
> opinionated on purpose and keeps the losing options visible so nobody "simplifies" them back in.
>
> Want to know **how the running system works** instead? The layered stack, how OSPF, iBGP,
> WireGuard and the anchor fit together? Read [`docs/`](docs/README.md). The docs explain the
> mechanism. This log explains the reasoning.

---

## 1. What changed and why

Origination moves from the **ERs (home)** to the **BRs (datacenters)**.

**Motivation**

- A home power outage or maintenance window shouldn't withdraw the prefix from the DFZ.
- A remote site attached to a BR has to survive home going dark.
- Future peerings shouldn't depend on a residential ISP for their value.

**Honest accounting of the trade**

| | Before (ER origination) | After (BR origination) |
|---|---|---|
| Home down | Prefix **withdrawn** globally | Prefix **stays announced**. Home traffic dropped at the BRs |
| BR can't deliver | Withdraws **automatically** (loses /24 from iBGP) | Withdraws **only** via the backbone + anchor-guard script |
| Remote site, home down | Dark | **Still works** |
| Upstream churn on home maintenance | Every time | Never |

You're swapping an *emergent* safety property for a *scripted* one. The anchor-guard script and
the monitoring in §11 aren't optional.

You also become a **black hole** instead of **invisible** when home is down. An end user gets a
timeout either way. The DFZ gets a lot less noise.

---

## 2. The three mechanisms

1. **Origination anchor.** Every BR holds `203.0.113.0/24` as a `blackhole` route at
   `distance=254` and originates from it via `output.network`. Distance 254 loses to everything.
   It only catches in-block space nothing else claims.

2. **The ERs advertise their attached block.** `203.0.113.0/25` goes into iBGP with
   next-hop-self, gated by a blackhole `home-anchor` that `home-anchor-guard` toggles on live-VIP
   presence (§13). Longest-prefix beats every BR's /24 blackhole. The last firewall VIP withdraws
   → the /25 is withdrawn → the BRs quietly fall back to the blackhole. **The /24 never moves
   upstream.**

3. **The BR↔BR backbone carries iBGP.** A BR whose home tunnels all died still reaches the ER
   loopbacks through a sibling BR. It keeps its iBGP sessions and the /25 and forwards (one extra
   DC hop) instead of black-holing. The remote-site design needs the same backbone.

**The rule:** *every router advertises what's attached to it. The BRs originate the aggregate
unconditionally. Longest-prefix-match does the rest.*

---

## 3. Topology changes from the previous build

| | Was | Now |
|---|---|---|
| iBGP topology | ERs as route reflectors, BRs as clients | **Full mesh. No route reflection.** |
| /24 origination | ERs, via `output.network` | **BRs**, via `output.network` + blackhole anchor |
| ER→iBGP advertisement | `203.0.113.0/24` | **`203.0.113.0/25`** (their customer block) |
| BR↔BR links | none | **full mesh WireGuard backbone**, OSPF cost 5 |
| ER /24 blackhole | origination anchor | **loop guard only**, never advertised |
| Default into iBGP | `default-originate=if-installed` | **eBGP-learned default, propagated by iBGP** |
| Withdrawal safety | emergent (BR loses /24 from iBGP) | **`anchor-guard`: two signals, two timers** (§6.5) |

### Why full mesh, and not route reflection

**`nexthop-choice=force-self` on a route reflector is invalid.** RFC 4456 says an RR leaves
NEXT_HOP alone on reflected routes. Make the BRs RRs for the ERs *and* full-mesh among
themselves and you get:

- br1 reflects er1's /25 to br2 with next-hop `br1-lo`
- br2 reflects er1's /25 to br1 with next-hop `br2-lo`
- br1 sees `br2-lo` at IGP cost **5** vs `er1-lo` at **10** → prefers the sibling
- br2 does the same → **br1 → br2 → br1 forwarding loop**

CLUSTER_LIST won't save you. It stops *advertisement* loops, not this.

In a **full mesh** nothing is reflected. A router never re-advertises an iBGP-learned route to
another iBGP peer. So `force-self` is correct everywhere, applied only by the router that
*originates* a prefix (the ERs on their /25, the BRs on their eBGP-learned default). Every router
sees every prefix with the true originator's next-hop and resolves it through OSPF.

6 routers → **15 sessions**. Trivial. Revisit RR around 12+ routers and configure it right then:
RRs preserve next-hop, only originators force-self.

---

## 4. Naming

Names describe **role**. Never **media** or **geography**. Changing ISPs, swapping fibre for
coax or moving a rack should never force a rename.

| Element | Convention | Examples |
|---|---|---|
| **Site** | 3–4 char code, no geography implied | `hdc` (Home Data Center), `ord1` (Vultr Lisle), `ord2` (HostHatch Equinix) |
| **Router** | `{role}{n}.{site}` | `br1.ord1`, `br2.ord2`, `er1.hdc`, `er2.hdc` |
| **Home WANs** | `wan1` = primary, `wan2` = backup | today wan1 = fibre, wan2 = 5G. Nothing depends on that. |
| **Tunnel iface** | named for the **far end**, from the local device's view | on `er1`: `wg-br1-wan1`. On `br1`: `wg-er1-wan1`. |
| **Interface list** | `tun-wan1`, `tun-wan2`, `tun-bb` | `tunnels` = all three |
| **Routing table** | `via-wan1`, `via-wan2` | |

**WAN preference is only OSPF cost.** wan1 = 10, wan2 = 100. BGP never mentions either.
Promoting wan2 to primary is a two-line cost change. Not a rename.

**WireGuard port ranges encode the WAN, not the medium.** BRs listen on `518xx` for wan1 tunnels
and `519xx` for wan2 tunnels. That's how two tunnels share one BR public IP. The destination port
differs so the ER's `chain=output` mangle rules can pin them to different WANs. Port assignments
are per BR, so every BR uses the same four: `51821` (er1-wan1), `51822` (er2-wan1), `51921`
(er1-wan2), `51922` (er2-wan2).

§7.1 covers the two design decisions that *do* still depend on what wan2 physically is.

---
## 5. Addressing (delta)

Adds the BR↔BR backbone. Everything else is the same as the previous plan.

### `203.0.113.160/28` — BR↔BR backbone /31s

| Link | /31 | Low side | High side |
|---|---|---|---|
| br1 ↔ br2 | `.160/31` | br1 `.160` | br2 `.161` |
| br1 ↔ br3 | `.162/31` | br1 `.162` | br3 `.163` |
| br1 ↔ br4 | `.164/31` | br1 `.164` | br4 `.165` |
| br2 ↔ br3 | `.166/31` | br2 `.166` | br3 `.167` |
| br2 ↔ br4 | `.168/31` | br2 `.168` | br4 `.169` |
| br3 ↔ br4 | `.170/31` | br3 `.170` | br4 `.171` |
| — | `.172–.175` | spare | |

### Backbone WireGuard port convention

On **br*x***, the interface facing **br*y*** listens on **`51100 + y`**.

So `br1`'s `wg-br2` listens on `51102` and its peer stanza points at br2's `51101`.
Unambiguous, and it scales to br5/br6 without renumbering.

### Full map (unchanged blocks, for reference)

| Block | Use |
|---|---|
| `203.0.113.0/25` | Home customer space. eBGP firewall(s) claim VIPs here. **The ERs advertise it into iBGP** as an aggregate. |
| `203.0.113.128/27` | Remote-site delegations (4 × /29) |
| `203.0.113.160/28` | **BR↔BR backbone /31s** (new) |
| `203.0.113.176/28` | Remote-site tunnel P2P /31s |
| `203.0.113.192/27` | BR↔ER tunnel P2P /31s (16 tunnels) |
| `203.0.113.224/28` | ER interconnect + firewall transit /29 (no VRRP, see §13) |
| `203.0.113.240/28` | Loopbacks: br1 `.241` br2 `.242` br3 `.243` br4 `.244` · site1-4 `.245`-`.248` · er1 `.249` er2 `.250` |

### OSPF cost model

| Link | Cost |
|---|---|
| **BR ↔ BR backbone** | **5** |
| BR ↔ ER over **wan1** (primary) | 10 |
| BR ↔ ER over **wan2** (backup) | 100 |
| er1 ↔ er2 interconnect | 1 |

Sanity check. The backbone must never steal traffic from a direct path:

- `br1 → br2` direct = **5** vs. `br1 → er1 → br2` = 10 + 10 = 20. Direct wins.
- `er1 → br2` direct = **10** vs. `er1 → br1 → br2` = 10 + 5 = 15. Direct wins.
- `er1 → br2` when er1's **wan1** tunnel to br2 is down: `er1 → er2 → br2` = 1 + 10 = **11**,
  vs. `er1 → br2` over **wan2** = 100. Stays on wan1 via er2. Correct.

---

### DNS — `example.net`

**Zones**

| Zone | Purpose | Delegation |
|---|---|---|
| `example.net` | Forward (A) | NS at your registrar |
| `113.0.203.in-addr.arpa` | Reverse (PTR) for `203.0.113.0/24` | **Delegate from ARIN.** Add NS records for this zone in ARIN Online against your `203.0.113.0/24` net handle |
| *(provider-held)* | Reverse for BR **WAN** addresses | Set in the **Vultr / HostHatch panel**. You don't own those PTRs. Point them at the same `example.net` names. |

**Convention:** the bare router name resolves to its **loopback**, the router's canonical
address. Interface addresses get `{interface}.{router}.{site}.example.net`. That mirrors the
interface naming in §4 exactly and makes a traceroute through your AS read like a description of
the path.

**No DNS names in router configs.** BGP, OSPF and `anchor-guard` all use literal IPs. A DNS
outage must never touch routing.

**Don't host both nameservers inside `203.0.113.0/24`.** If the network's down your DNS goes with
it, PTRs you'd want while debugging included. Keep at least one authoritative NS off-net.

#### Loopbacks — canonical router names (`203.0.113.240/28`)

| IP | Name |
|---|---|
| `.241` | `br1.ord1.example.net` |
| `.242` | `br2.ord2.example.net` |
| `.243` | `br3.<site>.example.net` *(future)* |
| `.244` | `br4.<site>.example.net` *(future)* |
| `.245` – `.248` | `sr1.<site>.example.net`, remote-site routers by site index 1-4 (§24) |
| `.249` | `er1.hdc.example.net` |
| `.250` | `er2.hdc.example.net` |

#### BR↔BR backbone (`203.0.113.160/28`)

| IP | Name |
|---|---|
| `.160` | `wg-br2.br1.ord1.example.net` |
| `.161` | `wg-br1.br2.ord2.example.net` |
| `.162` | `wg-br3.br1.ord1.example.net` |
| `.163` | `wg-br1.br3.<site>.example.net` |
| `.164` | `wg-br4.br1.ord1.example.net` |
| `.165` | `wg-br1.br4.<site>.example.net` |
| `.166` | `wg-br3.br2.ord2.example.net` |
| `.167` | `wg-br2.br3.<site>.example.net` |
| `.168` | `wg-br4.br2.ord2.example.net` |
| `.169` | `wg-br2.br4.<site>.example.net` |
| `.170` | `wg-br4.br3.<site>.example.net` |
| `.171` | `wg-br3.br4.<site>.example.net` |

#### BR↔ER tunnels (`203.0.113.192/27`)

| IP | Name | | IP | Name |
|---|---|---|---|---|
| `.192` | `wg-er1-wan1.br1.ord1` | | `.193` | `wg-br1-wan1.er1.hdc` |
| `.194` | `wg-er1-wan2.br1.ord1` | | `.195` | `wg-br1-wan2.er1.hdc` |
| `.196` | `wg-er2-wan1.br1.ord1` | | `.197` | `wg-br1-wan1.er2.hdc` |
| `.198` | `wg-er2-wan2.br1.ord1` | | `.199` | `wg-br1-wan2.er2.hdc` |
| `.200` | `wg-er1-wan1.br2.ord2` | | `.201` | `wg-br2-wan1.er1.hdc` |
| `.202` | `wg-er1-wan2.br2.ord2` | | `.203` | `wg-br2-wan2.er1.hdc` |
| `.204` | `wg-er2-wan1.br2.ord2` | | `.205` | `wg-br2-wan1.er2.hdc` |
| `.206` | `wg-er2-wan2.br2.ord2` | | `.207` | `wg-br2-wan2.er2.hdc` |
| `.208` | `wg-er1-wan1.br3.<site>` | | `.209` | `wg-br3-wan1.er1.hdc` |
| `.210` | `wg-er1-wan2.br3.<site>` | | `.211` | `wg-br3-wan2.er1.hdc` |
| `.212` | `wg-er2-wan1.br3.<site>` | | `.213` | `wg-br3-wan1.er2.hdc` |
| `.214` | `wg-er2-wan2.br3.<site>` | | `.215` | `wg-br3-wan2.er2.hdc` |
| `.216` | `wg-er1-wan1.br4.<site>` | | `.217` | `wg-br4-wan1.er1.hdc` |
| `.218` | `wg-er1-wan2.br4.<site>` | | `.219` | `wg-br4-wan2.er1.hdc` |
| `.220` | `wg-er2-wan1.br4.<site>` | | `.221` | `wg-br4-wan1.er2.hdc` |
| `.222` | `wg-er2-wan2.br4.<site>` | | `.223` | `wg-br4-wan2.er2.hdc` |

*(all `.example.net`)*

#### Home local links (`203.0.113.224/28`)

| IP | Name | Notes |
|---|---|---|
| `.224` | `ether3.er1.hdc.example.net` | ER interconnect |
| `.225` | `ether3.er2.hdc.example.net` | ER interconnect |
| `.233` | `ether4.er1.hdc.example.net` | firewall transit (er1) |
| `.234` | `ether4.er2.hdc.example.net` | firewall transit (er2) |
| `.235` | *(free)* | was the VRRP VIP; freed when VRRP was retired (§13) |
| `.236` | `fwa.hdc.example.net` | fwa, eBGP customer, transit peer address |

#### Remote-site delegations (`203.0.113.128/27`)

The `/29` is **attached** to the site router, which holds the first usable address as the inside
gateway (DNS `br-lan.sr1.<site>`). The other five belong to the site, routed directly with no
NAT. See §24.

| Block | Gateway | Name pattern |
|---|---|---|
| `.128/29` | `.129` | `br-lan.sr1.<site1>.example.net` |
| `.136/29` | `.137` | `br-lan.sr1.<site2>.example.net` |
| `.144/29` | `.145` | `br-lan.sr1.<site3>.example.net` |
| `.152/29` | `.153` | `br-lan.sr1.<site4>.example.net` |

#### Remote-site tunnels (`203.0.113.176/28`)

Every site holds a tunnel to **every** BR. No primary/backup (§24.1). Two `/31`s are reserved per
site so adding one never renumbers another. That's also why this `/28` is the hard ceiling on the
design: **four sites, two BRs, and a third BR doesn't fit.**

| IP | Name | | IP | Name |
|---|---|---|---|---|
| `.176` | `wg-<site1>.br1.ord1` | | `.177` | `wg-br1.sr1.<site1>` |
| `.178` | `wg-<site1>.br2.ord2` | | `.179` | `wg-br2.sr1.<site1>` |
| `.180` | `wg-<site2>.br1.ord1` | | `.181` | `wg-br1.sr1.<site2>` |
| `.182` | `wg-<site2>.br2.ord2` | | `.183` | `wg-br2.sr1.<site2>` |
| `.184` – `.187` | site3, same shape | | | |
| `.188` – `.191` | site4, same shape | | | |

#### Provider WAN addresses (outside your /24)

| IP | Name | PTR set where |
|---|---|---|
| `198.51.100.57` | `ether1.br1.ord1.example.net` | **Vultr panel** |
| *(HostHatch IP)* | `ether1.br2.ord2.example.net` | **HostHatch panel** |

These are the addresses the world actually sees in a traceroute *into* your AS. Also the ones in
abuse reports and mail headers. Get their PTRs right before any other record here. And they're the
one set you can't manage from your own zone.

#### Customer space (`203.0.113.0/25`)

Delegate as you like. These are the VIPs the firewall(s) claim over eBGP (§13). Anything here that
sends mail needs **forward-confirmed rDNS** (PTR → name, and that name's A → back to the same IP)
or it gets rejected.

---

## 6. Border Routers

Clean build. Both CHRs get torn down and rebuilt from this.

**These configs are generated.** See the `as64500/` generator bundle. What's printed here is
the generator's own output for `br1.ord1` with private keys redacted, so the doc can't drift from
what actually gets applied.

**Only five values differ between BRs.** Everything else is a byte-for-byte paste, connection
name (`ebgp-upstream`) and filter-chain name (`ebgp-out-upstream`) included. Only the chain
*contents* differ. So every verification command and every Ansible task works on any BR.

| | `br1.ord1`: Vultr | `br2.ord2`: HostHatch |
|---|---|---|
| Loopback / router-id | `203.0.113.241` | `203.0.113.242` |
| WAN address | `198.51.100.57` | `198.51.100.200` |
| Provider gateway | *(Vultr DHCP-assigned)* | `198.51.100.129` |
| **Peer ASN** | **`64515`** | **`65473`** |
| `ebgp-out-upstream` contents | §6.2a | §6.2b, **adds `65500:10000`** |

> **Both upstreams peer at the same multihop address `169.254.169.254` with different ASNs.**
> The easiest thing in the build to get wrong. Symptom: a session stuck in `Active` with nothing
> in the log to explain it.

### 6.1 Canonical BR config

```routeros
# =====================================================================
#  br1.ord1 — Border Router · vultr · AS64500
#  GENERATED by generate.py from topology.yml — DO NOT EDIT BY HAND.
#  CONTAINS PRIVATE KEYS. Do not commit.
# =====================================================================

/system/identity set name=br1.ord1

# --- services --------------------------------------------------------
/ip/service
set ftp           disabled=yes
set telnet        disabled=yes
set www           disabled=yes
set reverse-proxy disabled=yes
set api           disabled=yes
set api-ssl       disabled=yes
# SSH on, bound to mgmt. The kill switch and any Ansible workflow need it.
set ssh disabled=no address=<mgmt-prefix>

/ip/firewall/address-list
add list=mgmt address=<mgmt-prefix> comment="management"

# --- loopback: canonical address, BGP + OSPF router-id ----------------
/interface/bridge add name=lo0 protocol-mode=none
/ip/address add address=203.0.113.241/32 interface=lo0

# --- conntrack ON, transit NOT tracked --------------------------------
# It is the conntrack TABLE, not CPU, that kills a border router. raw runs
# before conntrack, so the transit fast path is untouched.
/ip/firewall/connection/tracking set enabled=yes
/ip/firewall/raw
add chain=prerouting action=notrack dst-address-type=!local \
    comment="transit is stateless; router-destined traffic stays tracked"
/ip/settings set rp-filter=loose

# --- provider default: present, never preferred, never advertised -----
/ip/dhcp-client set [find interface=ether1] default-route-distance=250

# --- eBGP peer pinned: MUST NOT resolve via the default route ---------
/ip/route
add dst-address=169.254.169.254/32 gateway=198.51.100.1 distance=1 \
    comment="eBGP peer"

# --- origination anchor (distance 254: loses to everything) -----------
/ip/firewall/address-list add list=my-aggregate address=203.0.113.0/24
/ip/route
add dst-address=203.0.113.0/24 blackhole distance=254 comment="anchor"

# --- WireGuard: tunnels to the ERs -----------------------------------
# No endpoint: the ERs are behind NAT and always initiate.
/interface/wireguard
add name=wg-er1-wan1 listen-port=51821 mtu=1360 private-key="<...>"
add name=wg-er1-wan2 listen-port=51921 mtu=1360 private-key="<...>"
add name=wg-er2-wan1 listen-port=51822 mtu=1360 private-key="<...>"
add name=wg-er2-wan2 listen-port=51922 mtu=1360 private-key="<...>"

/interface/wireguard/peers
add interface=wg-er1-wan1 public-key="<peer pub>" preshared-key="<psk>" allowed-address=0.0.0.0/0 persistent-keepalive=25s comment="er1 via wan1"
add interface=wg-er1-wan2 public-key="<peer pub>" preshared-key="<psk>" allowed-address=0.0.0.0/0 persistent-keepalive=25s comment="er1 via wan2"
add interface=wg-er2-wan1 public-key="<peer pub>" preshared-key="<psk>" allowed-address=0.0.0.0/0 persistent-keepalive=25s comment="er2 via wan1"
add interface=wg-er2-wan2 public-key="<peer pub>" preshared-key="<psk>" allowed-address=0.0.0.0/0 persistent-keepalive=25s comment="er2 via wan2"

/ip/address
add address=203.0.113.192/31 interface=wg-er1-wan1
add address=203.0.113.194/31 interface=wg-er1-wan2
add address=203.0.113.196/31 interface=wg-er2-wan1
add address=203.0.113.198/31 interface=wg-er2-wan2

# --- WireGuard: BR<->BR backbone -------------------------------------
/interface/wireguard
add name=wg-br2 listen-port=51102 mtu=1360 private-key="<...>"

/interface/wireguard/peers
add interface=wg-br2 public-key="<peer pub>" preshared-key="<psk>" endpoint-address=198.51.100.200 endpoint-port=51101 allowed-address=0.0.0.0/0 persistent-keepalive=25s comment="br2"

/ip/address
add address=203.0.113.160/31 interface=wg-br2

# --- interface lists --------------------------------------------------
/interface/list
add name=tun-wan1
add name=tun-wan2
add name=tun-bb
add name=tunnels include=tun-wan1,tun-wan2,tun-bb
/interface/list/member
add list=tun-wan1 interface=wg-er1-wan1
add list=tun-wan2 interface=wg-er1-wan2
add list=tun-wan1 interface=wg-er2-wan1
add list=tun-wan2 interface=wg-er2-wan2
add list=tun-bb interface=wg-br2

# --- OSPF: loopbacks + tunnel /31s only -------------------------------
# WG interfaces never go down on their own. OSPF hellos are the ONLY
# liveness detector in this network.
/routing/ospf/instance add name=core version=2 router-id=203.0.113.241
/routing/ospf/area add name=bb instance=core area-id=0.0.0.0
/routing/ospf/interface-template
add area=bb interfaces=lo0      passive
add area=bb interfaces=tun-bb   type=ptp cost=5 hello-interval=5s  dead-interval=20s
add area=bb interfaces=tun-wan1 type=ptp cost=10 hello-interval=5s  dead-interval=20s
add area=bb interfaces=tun-wan2 type=ptp cost=100 hello-interval=10s dead-interval=40s

# --- BGP instance: router-id lives HERE -------------------------------
# NOT on templates, NOT on connections. Instance also owns cluster-id,
# multipath (BGP ECMP) and vrf. Do NOT delete this menu -- it is current,
# not legacy. Deleting it takes your router-id with it.
/routing/bgp/instance
add name=core as=64500 router-id=203.0.113.241

# --- leave the `default` template BARE --------------------------------
# A connection with no templates= inherits `default`. Anything policy-shaped
# left there gets silently inherited by a session that should never have had it.
/routing/bgp/template set default output.filter-chain="" output.network=""

# --- iBGP: FULL MESH, no route reflection -----------------------------
# Templates carry protocol/policy ONLY. No local.*, no remote.*, no router-id.
# On templates the address-family parameter is `afi` (it is `address-families`
# on connections -- different menu, different name).
/routing/bgp/template
add name=ibgp afi=ip multihop=yes nexthop-choice=force-self \
    input.filter=ibgp-in output.filter-chain=ibgp-out

# local.address / local.role are CONNECTION-specific and cannot be templated,
# so they repeat on every session.
/routing/bgp/connection
add name=ibgp-br2 instance=core templates=ibgp \
    local.address=203.0.113.241 local.role=ibgp \
    remote.address=203.0.113.242 remote.as=64500
add name=ibgp-er1 instance=core templates=ibgp \
    local.address=203.0.113.241 local.role=ibgp \
    remote.address=203.0.113.249 remote.as=64500
add name=ibgp-er2 instance=core templates=ibgp \
    local.address=203.0.113.241 local.role=ibgp \
    remote.address=203.0.113.250 remote.as=64500

/routing/filter/rule
add chain=ibgp-in rule="accept"
# NEVER leak the aggregate into iBGP: every BR originates it locally.
add chain=ibgp-out rule="if (dst==203.0.113.0/24 && dst-len==24) { reject }"
add chain=ibgp-out rule="accept"

# --- eBGP upstream ----------------------------------------------------
# Name + filter-chain identical on every BR; only the chain CONTENTS differ.
# local.address is MANDATORY: without it RouterOS guesses and prefers the
# highest loopback, which is not what the provider expects.
/routing/bgp/template
add name=ebgp-up afi=ip multihop=yes \
    output.network=my-aggregate \
    output.network-blackhole=no \
    input.filter=ebgp-in output.filter-chain=ebgp-out-upstream

# output.network is documented as: "the network is sent only if a matching
# route exists in the routing table" -- that is EXACTLY what makes the anchor
# route the origination switch. network-blackhole=no is what stops RouterOS
# from creating its own blackhole and making anchor-guard a no-op.
/routing/bgp/connection
add name=ebgp-upstream instance=core templates=ebgp-up \
    local.address=198.51.100.57 local.role=ebgp \
    remote.address=169.254.169.254/32 remote.as=64515 \
    listen=yes connect=yes

/routing/filter/rule
add chain=ebgp-in rule="if (dst==0.0.0.0/0 && dst-len==0) { accept } reject"

# --- ebgp-out-upstream: the ONLY per-BR chain -------------------------
add chain=ebgp-out-upstream rule="if (bgp-large-communities includes 64500:3:64515) { reject }"
add chain=ebgp-out-upstream rule="if (bgp-large-communities includes 64500:2:3) { set bgp-path-prepend 3 }"
add chain=ebgp-out-upstream rule="if (bgp-large-communities includes 64500:2:2) { set bgp-path-prepend 2 }"
add chain=ebgp-out-upstream rule="if (bgp-large-communities includes 64500:2:1) { set bgp-path-prepend 1 }"
add chain=ebgp-out-upstream rule="jump ebgp-out"

# --- ebgp-out: shared tail. RTBH, strip internals, terminal reject. ---
add chain=ebgp-out rule="if (dst in 203.0.113.0/24 && dst-len==32 && bgp-large-communities includes 64500:1:666) { set bgp-large-communities \"\"; set bgp-communities 65535:666,no-export; accept }"
add chain=ebgp-out rule="if (dst==203.0.113.0/24 && dst-len==24) { set bgp-large-communities \"\"; accept }"
# Terminal reject: stops an untagged more-specific ever leaking upstream.
add chain=ebgp-out rule="reject"

# --- input filter. The forward chain stays EMPTY. ---------------------
/ip/firewall/filter
add chain=input action=accept connection-state=established,related
add chain=input action=accept protocol=icmp comment="PMTUD/QUIC - never break this"
add chain=input action=accept protocol=udp dst-port=51821,51822,51921,51922 comment="WG to ERs"
add chain=input action=accept protocol=udp dst-port=51102 comment="WG backbone"
add chain=input action=accept protocol=tcp dst-port=179 src-address=169.254.169.254
add chain=input action=accept in-interface-list=tunnels comment="WG-authenticated"
add chain=input action=accept src-address-list=mgmt
add chain=input action=drop

# --- anchor-guard: two signals, two timers ---------------------------
# Slow to withdraw (a flapping adjacency must not become a DFZ event),
# instant to re-originate.
/system/script
add name=anchor-guard policy=read,write,test source={
  :global agIsoFail
  :global agCustFail
  :if ([:typeof \$agIsoFail]  = "nothing") do={ :set agIsoFail  0 }
  :if ([:typeof \$agCustFail] = "nothing") do={ :set agCustFail 0 }

  :local peers { "203.0.113.242"; "203.0.113.249"; "203.0.113.250" }
  :local reachable 0
  :foreach p in=\$peers do={
    :if ([:len [/ip/route/find where dst-address=("\$p/32") && active]] > 0) do={
      :set reachable (\$reachable + 1)
    }
  }

  :local customers { "203.0.113.0/25" }
  :local delivered 0
  :foreach c in=\$customers do={
    :if ([:len [/ip/route/find where dst-address=\$c && active && blackhole=no]] > 0) do={
      :set delivered (\$delivered + 1)
    }
  }

  :if (\$reachable > 0) do={ :set agIsoFail  0 } else={ :set agIsoFail  (\$agIsoFail  + 1) }
  :if (\$delivered > 0) do={ :set agCustFail 0 } else={ :set agCustFail (\$agCustFail + 1) }

  :local pull false
  :if (\$agIsoFail  >= 6)  do={ :set pull true }
  :if (\$agCustFail >= 60) do={ :set pull true }

  :local down [/ip/route/find where comment="anchor" && disabled=yes]
  :if (\$pull) do={
    :if ([:len \$down] = 0) do={
      /ip/route/set [find where comment="anchor"] disabled=yes
      :log error ("anchor-guard: WITHDRAWING 203.0.113.0/24 reachable=\$reachable delivered=\$delivered")
    }
  } else={
    :if ([:len \$down] > 0) do={
      /ip/route/set [find where comment="anchor"] disabled=no
      :log warning ("anchor-guard: RE-ORIGINATING 203.0.113.0/24 reachable=\$reachable delivered=\$delivered")
    }
  }
}

# Enable ONLY after proving the anchor actually gates origination:
#   /ip/route/disable [find comment="anchor"]
#   /routing/bgp/advertisements/print peer=ebgp-upstream   <- must be EMPTY
#   /ip/route/enable  [find comment="anchor"]
# /system/scheduler add name=anchor-guard interval=10s on-event=anchor-guard policy=read,write,test
```

### 6.2 `ebgp-out-upstream` — the only per-BR chain

Both jump to the shared `ebgp-out` tail. It handles RTBH, strips internal large communities and
**ends in `reject`** so an untagged more-specific can never leak.

**(a) br1.ord1 → Vultr (AS64515).** No upstream communities. The generator emits just the
suppress/prepend rules and the jump.

**(b) br2.ord2 → HostHatch (AS65473).** The generator prepends one extra rule:

```routeros
add chain=ebgp-out-upstream rule="set bgp-communities 65500:10000"
```

`65500:10000` is **mandatory**. Without it HostHatch's DDoS scrubbing platform doesn't propagate
the announcement at all. It's *their* schema, sent to *them*. Not an internal tag, and it must
never go to Vultr.

**Test the RTBH interaction here.** `ebgp-out`'s blackhole rule does
`set bgp-communities 65535:666,no-export`. A **replace**, not an append. On the HostHatch chain it
overwrites `65500:10000` and your blackhole announcement may never clear their scrubber. RTBH
quietly failing on the one provider whose DDoS platform you're trying to talk to. If it clobbers,
use the combined form:
`set bgp-communities 65500:10000,65535:666,no-export`.

### 6.3 Build order

Rebuild br1 first. Leave br2's eBGP session `disabled=yes` until br1 is announcing again. You keep
a live prefix the whole time, and if br1 goes sideways you still have an AS.

1. Loopback, services, conntrack, rp-filter, provider default, peer /32.
2. Anchor + `my-aggregate`. Confirm `/ip/route/print where dst-address=203.0.113.0/24`.
3. eBGP up. Confirm `/routing/bgp/advertisements/print peer=ebgp-upstream`.
4. WireGuard, OSPF, iBGP. Confirm the ERs' `/25` lands in the RIB.
5. Prove the anchor gates origination (§6.5). **Then** enable the `anchor-guard` scheduler.
6. Rebuild br2. Enable its session. Confirm both are announcing.

### 6.4 Seven decisions that must not be "simplified" away

Every one was learned the hard way or fails silently. On a rebuild they're exactly the things
that look redundant and get dropped.

| Decision | What breaks without it |
|---|---|
| **BGP is a three-object model**: `instance` = router-id/as/cluster-id/multipath/vrf · `template` = afi/multihop/nexthop-choice/input.*/output.* · `connection` = local.*/remote.*/listen/connect | Put a property in the wrong menu and RouterOS rejects it. **`router-id` is instance-only.** On templates the address-family parameter is `afi`, not `address-families`. Templates carry **no** `local.*` or `remote.*`, so `local.address` and `local.role` repeat on every connection. **`/routing/bgp/instance` isn't legacy. Delete it and your router-id goes with it.** |
| `local.address` pinned to the WAN address | RouterOS guesses, prefers the **highest loopback** and the provider stops recognising the session. Killed the Vultr session once already. Adding a loopback makes it *more* likely, not less. |
| `169.254.169.254/32` static via the provider gateway | With the default demoted, the BGP default's next-hop resolves only via itself → **permanent recursion flap**. |
| Provider default at `distance=250` | A BR with dead eBGP keeps advertising a default to the ERs. The provider then drops your /24-sourced traffic at their filter. |
| `output.network-blackhole=no` + explicit anchor | The docs are explicit. `output.network` sends the prefix *"only if a matching route exists in the routing table"* and `network-blackhole=yes` makes RouterOS **create that route itself**. Leave it on and toggling your anchor does nothing → **anchor-guard is a silent no-op** that logs `WITHDRAWING` while the BR keeps announcing. |
| `default` BGP template left **bare** | A connection with no `templates=` inherits it. An iBGP session that inherits `network=originate` tries to originate the /24 to your ERs. One that inherits an eBGP output filter refuses to carry the default route. Sessions establish. Everything looks healthy. Nothing works. |
| conntrack ON but transit `notrack`'d | Tracking transit exposes the conntrack **table** (not CPU) to every scanner on the internet. And it re-arms the `connection-state=invalid` drop behind the original SYN-retransmission bug. |

**`local.role` has no `ibgp-rr-client`.** Valid roles: `ebgp`, `ebgp-customer`, `ebgp-peer`,
`ebgp-provider`, `ebgp-rs`, `ebgp-rs-client`, `ibgp`, `ibgp-rr`. One more reason full mesh is the
right call.

**Optional: `use-bfd=yes` on the templates** (it's a template property) if you'd rather have BFD
than tight OSPF timers. And **`multipath=<n>` on the instance** for BGP ECMP.

### 6.5 `anchor-guard` — two signals, two timers

The generator emits the script but leaves the **scheduler commented out**. On purpose.

Two separate questions because they have **different right answers**:

| Signal | Question | Withdraw after | Why that timer |
|---|---|---|---|
| **Isolation** | Can I reach *any* router in AS64500? (OSPF) | **60s** | I'm an island. My siblings are healthy and can take this traffic **now**. Move fast. |
| **No customer** | Do I have an active route to *any* customer prefix? (iBGP/static) | **10 min** | Nobody in the AS can deliver. A DFZ event, not a local one. Go slow. |

**Don't** trigger on "did I lose the ER's /25". That brings back the exact home dependency this
design removes. An 11-minute home outage would withdraw the prefix from every BR, kill every remote
site and hand you back the flap, ten minutes late. Counting *any customer prefix* is what lets a
live remote site hold the prefix up while home is dark.

**You need the hysteresis.** Slow to withdraw, instant to re-originate. Otherwise one flapping OSPF
adjacency becomes the upstream prefix flap you built this to prevent.

**Prove the linchpin before you enable the scheduler:**

```
/ip/route/disable [find comment="anchor"]
/routing/bgp/advertisements/print peer=ebgp-upstream     # /24 must be GONE
/ip/route/enable  [find comment="anchor"]
/routing/bgp/advertisements/print peer=ebgp-upstream     # /24 must be BACK
```

If the /24 is still advertised with the anchor disabled, `output.network-blackhole` didn't take.
**anchor-guard is a silent no-op** and every failure guarantee in §8 is fiction.

Plan B if your build behaves differently: have the script add/remove the /24 from the
`my-aggregate` address-list instead of toggling the route. Property names in `/ip/route/find` also
drift between ROS7 releases. Check `blackhole` and `disabled` against 7.23.2 first.

---

## 7. Edge Router — `er1.hdc`

> **Partly superseded by [§13](#13-vrrp-retired--bgp-is-the-reachability-and-health-signal).** This
> listing predates the VRRP retirement. The VRRP interface/VIP, the `check-gateway=ping` `/25` static
> and pfSense as the customer default gateway are all gone. The ER now originates the `/25` off a
> blackhole `home-anchor` toggled by `home-anchor-guard`, learns VIPs from `fwa` over eBGP and hands
> `fwa` a default. Regenerate from `topology.yml` for the current output. Kept as the record of the
> earlier design.

Generator output for `er1`, keys redacted.

```routeros
# =====================================================================
#  er1.hdc — Edge Router · AS64500
#  GENERATED by generate.py from topology.yml — DO NOT EDIT BY HAND.
#  CONTAINS PRIVATE KEYS. Do not commit.
# =====================================================================

/system/identity set name=er1.hdc

/ip/service
set ftp           disabled=yes
set telnet        disabled=yes
set www           disabled=yes
set reverse-proxy disabled=yes
set api           disabled=yes
set api-ssl       disabled=yes
set ssh disabled=no address=<mgmt-prefix>

/ip/firewall/address-list
add list=mgmt address=<mgmt-prefix> comment="management"

/interface/bridge add name=lo0 protocol-mode=none
/ip/address add address=203.0.113.249/32 interface=lo0

/ip/firewall/connection/tracking set enabled=yes
/ip/firewall/raw
add chain=prerouting action=notrack dst-address-type=!local \
    comment="transit is stateless; router-destined traffic stays tracked"
/ip/settings set rp-filter=loose

# --- WANs. wan1 = primary, wan2 = backup. Media-agnostic: preference is
#     expressed ONLY as OSPF cost, never in BGP.
/ip/address
add address=192.168.1.11/24 interface=ether1 comment="wan1"
add address=192.168.12.11/24 interface=ether2 comment="wan2"

# --- WireGuard: one interface per BR per WAN --------------------------
# The BR's LISTEN PORT selects the WAN: 518xx = wan1, 519xx = wan2. That is
# what lets two tunnels share one BR public IP -- the dst port differs, so
# the mangle rules below can pin them to different WANs.
/interface/wireguard
add name=wg-br1-wan1 listen-port=51001 mtu=1360 private-key="<...>"
add name=wg-br1-wan2 listen-port=51101 mtu=1360 private-key="<...>"
add name=wg-br2-wan1 listen-port=51002 mtu=1360 private-key="<...>"
add name=wg-br2-wan2 listen-port=51102 mtu=1360 private-key="<...>"

/interface/wireguard/peers
add interface=wg-br1-wan1 public-key="<peer pub>" preshared-key="<psk>" endpoint-address=198.51.100.57 endpoint-port=51821 allowed-address=0.0.0.0/0 persistent-keepalive=25s comment="br1 via wan1"
add interface=wg-br1-wan2 public-key="<peer pub>" preshared-key="<psk>" endpoint-address=198.51.100.57 endpoint-port=51921 allowed-address=0.0.0.0/0 persistent-keepalive=25s comment="br1 via wan2"
add interface=wg-br2-wan1 public-key="<peer pub>" preshared-key="<psk>" endpoint-address=198.51.100.200 endpoint-port=51821 allowed-address=0.0.0.0/0 persistent-keepalive=25s comment="br2 via wan1"
add interface=wg-br2-wan2 public-key="<peer pub>" preshared-key="<psk>" endpoint-address=198.51.100.200 endpoint-port=51921 allowed-address=0.0.0.0/0 persistent-keepalive=25s comment="br2 via wan2"

/ip/address
add address=203.0.113.193/31 interface=wg-br1-wan1
add address=203.0.113.195/31 interface=wg-br1-wan2
add address=203.0.113.201/31 interface=wg-br2-wan1
add address=203.0.113.203/31 interface=wg-br2-wan2

/interface/list
add name=tun-wan1
add name=tun-wan2
add name=tunnels include=tun-wan1,tun-wan2
/interface/list/member
add list=tun-wan1 interface=wg-br1-wan1
add list=tun-wan2 interface=wg-br1-wan2
add list=tun-wan1 interface=wg-br2-wan1
add list=tun-wan2 interface=wg-br2-wan2

# --- ER interconnect + pfSense transit + VRRP ------------------------
/ip/address
add address=203.0.113.224/31 interface=ether3 comment="er interconnect"
add address=203.0.113.233/29 interface=ether4 comment="pfSense transit"

/interface/vrrp add name=vrrp-wan interface=ether4 vrid=10 priority=200 version=3
/ip/address add address=203.0.113.235/29 interface=vrrp-wan comment="pfSense default gw"

# --- pin each tunnel family to its WAN -------------------------------
# chain=output only. Never touches the transit fast path.
/routing/table
add name=via-wan1 fib
add name=via-wan2 fib

/ip/firewall/mangle
add chain=output action=mark-routing new-routing-mark=via-wan1 passthrough=no \
    protocol=udp dst-port=51820-51829 comment="WG outer -> wan1"
add chain=output action=mark-routing new-routing-mark=via-wan2 passthrough=no \
    protocol=udp dst-port=51920-51929 comment="WG outer -> wan2"

/ip/route
add dst-address=0.0.0.0/0 gateway=192.168.1.1 routing-table=via-wan1
add dst-address=0.0.0.0/0 gateway=192.168.12.1 routing-table=via-wan2
# main-table /32s: management path to the BR publics, and a safe landing spot
# for any WG packet that escapes the marks (otherwise it recurses into a tunnel).
add dst-address=198.51.100.57/32 gateway=192.168.1.1 distance=1  comment="br1 via wan1"
add dst-address=198.51.100.57/32 gateway=192.168.12.1 distance=10 comment="br1 via wan2"
add dst-address=198.51.100.200/32 gateway=192.168.1.1 distance=1  comment="br2 via wan1"
add dst-address=198.51.100.200/32 gateway=192.168.12.1 distance=10 comment="br2 via wan2"

# --- what this ER advertises: its attached customer block -------------
# One list drives everything it originates: the permanent /25 plus ad-hoc
# RTBH /32s. output.network takes a single list.
/ip/firewall/address-list
add list=advertise address=203.0.113.0/25 comment="home customer block"

/ip/route
# check-gateway is the liveness signal: pfSense stops answering -> route goes
# inactive -> the /25 is withdrawn -> the BRs fall back to their blackhole.
add dst-address=203.0.113.0/25 gateway=203.0.113.236 \
    check-gateway=ping comment="home customer space -> pfSense"
# LOOP GUARD, not an origination anchor. Never advertised (filter rejects it).
add dst-address=203.0.113.0/24 blackhole distance=254 comment="loop guard"

# --- OSPF. WAN preference is ENTIRELY this cost. BGP never mentions it.
/routing/ospf/instance add name=core version=2 router-id=203.0.113.249
/routing/ospf/area add name=bb instance=core area-id=0.0.0.0
/routing/ospf/interface-template
add area=bb interfaces=lo0 passive
add area=bb interfaces=ether4 passive comment="pfSense transit"
add area=bb interfaces=ether3 type=ptp cost=1
add area=bb interfaces=tun-wan1 type=ptp cost=10 hello-interval=5s  dead-interval=20s
add area=bb interfaces=tun-wan2 type=ptp cost=100 hello-interval=10s dead-interval=40s

# --- BGP instance: router-id lives HERE, not on templates/connections.
/routing/bgp/instance
add name=core as=64500 router-id=203.0.113.249

# A connection with no templates= inherits `default`. Keep it bare.
/routing/bgp/template set default output.filter-chain="" output.network=""

# --- iBGP: FULL MESH. This ER originates its /25, so force-self is right.
# Templates hold protocol/policy only -- `afi` (not address-families), no
# local.*/remote.*, no router-id.
/routing/bgp/template
add name=ibgp afi=ip multihop=yes nexthop-choice=force-self \
    output.network=advertise \
    input.filter=ibgp-in output.filter-chain=ibgp-out

/routing/bgp/connection
add name=ibgp-br1 instance=core templates=ibgp \
    local.address=203.0.113.249 local.role=ibgp \
    remote.address=203.0.113.241 remote.as=64500
add name=ibgp-br2 instance=core templates=ibgp \
    local.address=203.0.113.249 local.role=ibgp \
    remote.address=203.0.113.242 remote.as=64500
add name=ibgp-er2 instance=core templates=ibgp \
    local.address=203.0.113.249 local.role=ibgp \
    remote.address=203.0.113.250 remote.as=64500

/routing/filter/rule
add chain=ibgp-in rule="accept"
# any /32 out of our own space is an RTBH request -- tag it
add chain=ibgp-out rule="if (dst in 203.0.113.0/24 && dst-len==32) { set bgp-large-communities 64500:1:666; accept }"
add chain=ibgp-out rule="if (dst==203.0.113.0/24 && dst-len==24) { reject }"
add chain=ibgp-out rule="accept"

# --- MSS clamp. The one thing allowed in the forward chain. -----------
/ip/firewall/mangle
add chain=forward action=change-mss new-mss=1320 passthrough=yes \
    protocol=tcp tcp-flags=syn tcp-mss=1321-65535 out-interface-list=tunnels
add chain=forward action=change-mss new-mss=1320 passthrough=yes \
    protocol=tcp tcp-flags=syn tcp-mss=1321-65535 in-interface-list=tunnels

# --- input -----------------------------------------------------------
/ip/firewall/filter
add chain=input action=accept connection-state=established,related
add chain=input action=accept protocol=icmp comment="PMTUD/QUIC - never break this"
add chain=input action=accept in-interface-list=tunnels
add chain=input action=accept in-interface=ether3
add chain=input action=accept in-interface=ether4
add chain=input action=accept src-address-list=mgmt
add chain=input action=drop in-interface=ether1
add chain=input action=drop in-interface=ether2
```

**er2.hdc:** identical, with loopback/router-id `.250`, its own ER-side /31s
(`.197 .199 .205 .207 .213 .215 .221 .223`), transit `.234/29`, interconnect `.225/31` and peers
pointing at BR ports **51822 / 51922**. Same template.

**The ERs run their own guard, `home-anchor-guard`** (§13). They originate only their own /25, and
that now rides on whether any customer VIP is a live eBGP route. Not on a ping.

### 7.1 What is media-agnostic, and what isn't

The names are. Two design decisions **aren't**. They're properties of the *current* links, so
revisit them if you change what wan1 or wan2 actually is:

**wan2 is CGNAT'd, which is why WireGuard isn't optional.** GRE can't traverse NAT and a BR can't
initiate toward a CGNAT'd ER. The ERs always initiate with `persistent-keepalive` and the BR peers
carry no `endpoint-address`. If wan2 ever gets a static public IP this constraint relaxes. No
reason to act on it though.

**wan2's OSPF timers are looser** (`hello 10s / dead 40s` vs `5s / 20s`). On purpose. A jittery
mobile link flaps an adjacency with aggressive timers. On a stable backup link you'd tighten them
to match wan1.

Everything else (cost 10 vs 100, port ranges, routing marks, the failover behaviour in §8) depends
only on *which WAN is primary*. Not on what it's made of.

---

## 8. Failure matrix

| Event | /24 in the DFZ | Behaviour |
|---|---|---|
| **Steady state** | Announced by all 4 BRs | iBGP /25 (next-hop = ER loopback) beats every BR's /24 blackhole. Traffic reaches home. |
| **Home blip / maintenance (< 10 min)** | **Announced, all 4 BRs. No flap.** | ER iBGP sessions drop → /25 withdrawn → BRs fall back to their blackhole. Home traffic gets dropped at the BRs for the duration. The DFZ sees nothing. **This is the case the whole design exists for.** |
| **Home down > 10 min, no remote sites** | **All 4 withdraw** (no-customer guard) | Nothing in the AS can deliver anything. Withdrawing is correct. |
| **Home down > 10 min, remote site alive** | **Announced, all 4 BRs** | The site's /29 is an active customer prefix on every BR (local static on its own BR, iBGP elsewhere). The no-customer guard never fires. **The site keeps working while home is dark.** |
| **br1 loses all 4 home tunnels; backbone OK** | Announced | br1's iBGP to the ERs is loopback-to-loopback and OSPF resolves `er1-lo` **via br2 across the backbone**. The sessions survive and br1 keeps the /25. It forwards home traffic through br2. One extra DC hop. No withdrawal, no blackhole. |
| **br1 loses home tunnels AND backbone** | **br1 withdraws after 60s** (isolation guard) | Zero reachable AS peers → anchor disabled. The other three keep announcing and traffic moves to them fast because they're healthy. |
| **br1's eBGP to Vultr drops** | br1's announcement gone (session down) | BGP default withdrawn → br1 stops offering a default over iBGP → ERs shift egress. The distance-250 DHCP default keeps br1 manageable but is never advertised. A site attached to br1 egresses via a sibling BR over the backbone. |
| **fwa loses its session to one ER** | Announced | er1 loses the VIP /32. er2 still holds it and er1 relearns it over the interconnect. Inbound shifts to er2 and the /25 never withdraws. Egress just drops er1 from the firewall's ECMP set. (§13) |
| **fwa dies entirely (or every firewall does)** | Announced through a short outage | All VIP sessions drop → both ERs' `home-anchor-guard` disables the `home-anchor` → the /25 leaves iBGP → BRs fall back to their blackhole. Withdraws the /24 only if it stays down past the BRs' 10-min no-customer timer, so a brief outage is invisible to the DFZ. (§13) |
| **wan1 CPE dies** | Announced | All `*-wan1` tunnels drop. Only the cost-100 `*-wan2` paths remain. Both directions move to wan2. |
| **All BRs isolated from home and each other** | **All withdraw** (60s) | Correct. Nobody can deliver. |

---

## 9. BGP communities

### 9.1 Two kinds of community. Do not conflate them.

**Communities you SEND to an upstream** are defined by *them*. Use whatever they specify in
whatever format they specify.

| Community | Upstream | Purpose | Status |
|---|---|---|---|
| `65500:10000` | **HostHatch** | Required to get the announcement past their DDoS scrubbing platform. **Without it the prefix does not propagate at all.** | **KEEP.** Goes in `ebgp-out-hosthatch` only. Means nothing to Vultr. |

Not an internal tag. Don't "modernise" it into a large community. It's HostHatch's schema, sent to
HostHatch, and without it nothing propagates.

**Communities YOU define for your own routers to act on** are a different namespace. And here's
the problem:

> **A standard BGP community is 16 bits of ASN + 16 bits of value. 64500 needs 32 bits. It doesn't fit.**

So all *internal* tags use **large communities** (RFC 8092): `64500:<function>:<value>`.
RouterOS 7.23.2 exposes these as `bgp-large-communities`.

| Large community | Meaning | Acted on by |
|---|---|---|
| `64500:1:666` | **RTBH**: blackhole this /32 at every upstream | BRs → translate to each upstream's blackhole community |
| `64500:1:1xxx` | Origin site tag (1001 hdc, 1002 ord1, 1003 ord2) | nobody. Informational, for troubleshooting |
| `64500:2:1` `:2:2` `:2:3` | Prepend ×1 / ×2 / ×3 to **all** upstreams | BRs |
| `64500:3:<asn>` | Do **not** announce to upstream ASN `<asn>` | BRs |

Everything in that table is real **route policy**, a property of a prefix you're actually
advertising. That's what communities are for.

The two never collide. Internal large communities are **stripped on eBGP egress** (§9.3) and the
upstream's own standard communities get set there at the same moment.

### 9.2 What communities cannot do here

Tempting idea: tag a route from the ERs with "don't advertise from br1" and pull an announcement
without logging into a BR. **It can't work. Structural reasons:**

1. **Communities ride on prefixes and there's no prefix to ride.** The ERs advertise the **/25**.
   The /24 is originated *locally* on each BR from its blackhole anchor. Nothing carrying a /24
   leaves home.
2. **No route-map can gate a local origination.** The obvious workaround is sending a /24 over
   iBGP with a suppress community and testing for it in `ebgp-out`. It fails because **BGP
   best-path prefers locally originated routes over peer-learned ones**. The BR's own `network`
   route wins, the tagged iBGP /24 never becomes the route the output filter sees and the filter
   is blind to it.
3. **It fails open.** Home goes down → the /25 is withdrawn → the community vanishes → the BR you
   suppressed **un-suppresses itself**. A kill switch that disarms when your control plane dies is
   worse than none, because you'll believe it's still armed.
4. **Two controllers, one actuator.** `anchor-guard` already owns the anchor's `disabled` flag on
   a 10-second timer. A second independent state machine writing that same flag is a bug factory.
   The kind that only shows up during the incident you built it for.

**The principle:** communities are *metadata about a route*. Not *RPC to a device*. Suppressing a
BR's origination is **device state**, not route policy. A config-management problem wearing a
routing-protocol costume. See §10.

`64500:3:<asn>` in the table above **is** the legit version of this instinct. "Don't announce
*this prefix* to *that upstream*" is real policy and it works, because it's a property of a prefix
you're actually advertising.

### 9.3 RTBH — script-free, BGP-native, and worth it

With four upstreams and a /24 you'll eventually want to null one host under attack from one
place. This is what communities are *for*.

**ER: inject the blackhole (the whole operator workflow):**

```routeros
/ip/route
add dst-address=203.0.113.130/32 blackhole comment="rtbh"
/ip/firewall/address-list
add list=advertise address=203.0.113.130 comment="rtbh"
add list=rtbh    address=203.0.113.130 comment="rtbh"
```

**You need all three lines and the `rtbh` one is the tag.** The `advertise` list drives
`output.network`. The blackhole route makes it active. The `ibgp-out-br` filter in §7 tags the /32
with `64500:1:666` **only if it's on the `rtbh` address-list**. To undo, delete all three.

> **This used to be two lines. The third is the point.** The filter used to tag *any* /32 out of
> `203.0.113.0/24` as RTBH and infer intent from prefix length. Safe only while nothing else in the
> AS originated a /32. Customer firewalls (§11) now claim VIP /32s out of `203.0.113.0/25` over
> eBGP, and under the old rule every claim quietly became a blackhole request nulled at every
> upstream. The exact opposite of what the customer asked for. No error anywhere. **RTBH is
> explicit now.** A /32 is a blackhole request only when an operator put it on the `rtbh` list.
> Add the blackhole route and the `advertise` entry but forget `rtbh`, and the /32 goes out as an
> ordinary more-specific and **isn't blackholed**. `ibgp-out-br` denies it to the BRs anyway, so it
> goes nowhere. Forgetting fails closed. Right direction.

**BR: the common chain (same on every BR):**

```routeros
/routing/filter/rule
# A more-specific leaves ONLY if it carries our RTBH tag. Strip the internal
# large-community on the way out; set the one the upstream honours.
add chain=ebgp-out rule="if (dst in 203.0.113.0/24 && dst-len==32 && \\
    bgp-large-communities includes 64500:1:666) \\
    { set bgp-large-communities \\"\\"; set bgp-communities 65535:666,no-export; accept }"

# the aggregate
add chain=ebgp-out rule="if (dst==203.0.113.0/24 && dst-len==24) \\
    { set bgp-large-communities \\"\\"; accept }"

# everything else -- including any UNTAGGED more-specific -- is rejected.
# This is what stops a fat-fingered static from leaking a /32 upstream.
# The live `bgp-out` chain has no terminal reject. Add it.
add chain=ebgp-out rule="reject"
```

**BR: per-upstream chains. This is where the upstream's own communities go.**

```routeros
# --- br1.ord1 -> Vultr (AS64515) -------------------------------------
/routing/filter/rule
add chain=ebgp-out-vultr rule="if (bgp-large-communities includes 64500:3:64515) { reject }"
add chain=ebgp-out-vultr rule="if (bgp-large-communities includes 64500:2:3) { set bgp-path-prepend 3 }"
add chain=ebgp-out-vultr rule="if (bgp-large-communities includes 64500:2:2) { set bgp-path-prepend 2 }"
add chain=ebgp-out-vultr rule="if (bgp-large-communities includes 64500:2:1) { set bgp-path-prepend 1 }"
add chain=ebgp-out-vultr rule="jump ebgp-out"

/routing/bgp/connection set [find name=ebgp-vultr] output.filter-chain=ebgp-out-vultr

# --- br2.ord2 -> HostHatch -------------------------------------------
# 65500:10000 is MANDATORY here: without it HostHatch's DDoS scrubbing
# platform does not propagate the announcement at all. It is their schema,
# not ours -- a standard community, set at eBGP egress, and it must survive
# the large-community strip in `ebgp-out` (it will: they are separate
# attributes, and `set bgp-communities` in ebgp-out only fires on RTBH /32s).
#
# Set it BEFORE the jump so it applies to the aggregate and to RTBH /32s alike.
/routing/filter/rule
add chain=ebgp-out-hosthatch rule="set bgp-communities 65500:10000"
add chain=ebgp-out-hosthatch rule="if (bgp-large-communities includes 64500:3:65473) { reject }"
add chain=ebgp-out-hosthatch rule="if (bgp-large-communities includes 64500:2:3) { set bgp-path-prepend 3 }"
add chain=ebgp-out-hosthatch rule="if (bgp-large-communities includes 64500:2:2) { set bgp-path-prepend 2 }"
add chain=ebgp-out-hosthatch rule="if (bgp-large-communities includes 64500:2:1) { set bgp-path-prepend 1 }"
add chain=ebgp-out-hosthatch rule="jump ebgp-out"

/routing/bgp/connection set [find name=ebgp-hosthatch] output.filter-chain=ebgp-out-hosthatch
```

**Watch the RTBH interaction on HostHatch.** `ebgp-out`'s RTBH rule does
`set bgp-communities 65535:666,no-export`. A *replace*, not an append. On the HostHatch path it
would **overwrite `65500:10000`** and the blackhole announcement may not clear their scrubbing
platform. Check the ordering on a live session. If it clobbers, set both in one action on the
HostHatch chain:
`set bgp-communities 65500:10000,65535:666,no-export`.

### 9.4 RTBH caveats — check these before you rely on it

**`65535:666` is the well-known BLACKHOLE community (RFC 7999). Confirm each provider honours
it.** Several want their own. Check with Vultr and HostHatch and keep a per-upstream note. The
rule above is a placeholder until you have.

**Your upstream has to accept a /32 from you at all.** Providers normally filter your
announcements to your registered prefix at max-length 24. Customer-triggered RTBH is a deliberate
exception on a separate relaxed filter. **Confirm each provider actually supports it** or the
announcement gets quietly dropped and you'll think RTBH works.

**Your ROA has maxLength 24, so an RTBH /32 is RPKI-invalid.** Most providers exempt blackhole
announcements from validation since the route carries NO_EXPORT and never reaches the DFZ. Confirm
it. **Don't widen your ROA to maxLength 32 to "fix" it.** That opens you to
hijack-by-more-specific, a far worse problem than the one you'd be solving.

**If an upstream ignores the community the traffic still arrives.** It reaches your BR, crosses
the tunnel to the ER and dies on the ER's blackhole *after* eating your home bandwidth. The exact
thing RTBH exists to protect. Checking each provider's support beats any amount of config.

---

## 10. Operations — removing an announcement

**Kill switch = disable the eBGP session.** One command, from home, over the loopback:

```
ssh 203.0.113.241 '/routing/bgp/connection set [find name=ebgp-vultr] disabled=yes'
```

Persistent. Survives reboots and home outages. And it **doesn't fight `anchor-guard`**, which
only ever touches the anchor *route*. That separation is on purpose. Keep it.

**Corollary: never build a manual kill switch around disabling the anchor route.** `anchor-guard`
will helpfully re-enable it within ten seconds.

If the real objection is *"manual edits drift from my source of truth"*, that's the right
objection. The answer is **Ansible + git**, not a BGP-signalled RPC. It solves this knob and
every other knob, it's auditable, and reverting is a `git revert` instead of remembering which
router you poked at 2am.

---

## 11. Monitoring

`anchor-guard` handles the two failure modes on its own now, so monitoring is no longer the only
thing between you and a silent black hole. It's still how you find out something *quietly
degraded* instead of failed:

- **Alert on any `anchor-guard` log line.** `WITHDRAWING` and `RE-ORIGINATING` should both
  be rare and loud.
- **Alert if one BR lacks the iBGP `203.0.113.0/25` while the others have it.** Per §8 that
  can't happen with the backbone up. If you ever see it the backbone or its OSPF adjacency is
  broken and you're one failure from a real outage.
- **Watch OSPF adjacency count per BR.** Should be 4 (2 ER-wan1 + 2 ER-wan2) + 3 backbone = **7**.
- **Watch BFD session count and state** (once §19 is armed). Should be **14** per BR, one per
  family per adjacency, all up. A *down* BFD session under an *up* OSPF adjacency means one end is
  missing pass 1. See §19.5. **One family up and the other down on the same link** is a different
  fault. Not BFD. v4 or v6 is broken on that tunnel by itself. Check `allowed-address` and the
  per-family firewall before touching `/routing/bfd` (§19.4).
- **On an ER, watch the customer-transit BFD sessions separately** (once §19.7 is armed). **Two per
  flagged firewall**, v4 and v6, both up. The only BFD sessions in the AS whose far end this build
  doesn't write, so a down one is as likely a firewall change as a link fault. While it's down that
  firewall's VIPs are back on the 3-minute BGP hold time. You quietly lose the failover speed the
  pair exists for.
- **Watch the anchor's `disabled` flag.** Should be `no` basically always.
- **Watch `/routing/bgp/advertisements` toward each upstream.** The /24 should be there.

How the data gets out: [§28](#28-snmpv3--the-collection-half-of-11). SNMPv3, authPriv,
read-only, polled by Zabbix. Read §28.7 before you trust a green dashboard. **None of the checks
in this list are reachable over SNMP.** They're BGP, OSPF and BFD state and the MikroTik MIB
carries none of it.

---

## 12. Gotchas

*All of this was learned the hard way so you get to learn it the cheap way.*

**Route reflection + `force-self` = forwarding loop.** See §3. That's why the iBGP is a full
mesh. If you ever bring RRs back they must **not** rewrite NEXT_HOP on reflected routes (RFC
4456). Otherwise two RRs each point at the other's loopback, which is cheaper in IGP metric than
the true originator, and loop.

**Don't trigger withdrawal on "I lost the ER's /25".** It looks like the obvious signal and it
quietly brings back the home dependency this whole design removes. The right signal is *"can I
deliver to **any** customer prefix"*. A live remote site satisfies that even when home is dark.
See §6.5.

**Communities are metadata about a route, not RPC to a device.** Read §9.2 before you try to
signal "stop announcing" from the ERs. Structurally unworkable *and* fails open.

**Two community namespaces and they aren't interchangeable.** `65500:10000` is **HostHatch's**,
required to clear their DDoS platform. Keep it, on the HostHatch chain only. Your *internal* tags
must be **large** communities because AS64500 doesn't fit in a standard one. See §9.1. And check
the RTBH rule's `set bgp-communities` doesn't clobber `65500:10000` on the HostHatch path. It's a
replace, not an append.

**The `ebgp-out` chain must end in `reject`.** Otherwise an untagged more-specific out of your own
space (a fat-fingered static, a leaked /32) walks straight upstream. The live `bgp-out` chain has
no terminal reject today.

**Leave the `default` BGP template bare.** Every new connection inherits it. Put an output filter
or a `network=` origination on it and an iBGP session inherits them without a word. It comes up,
tries to originate the /24 to your ERs and refuses to carry the default route or the /25. Sessions
establish. Everything looks healthy. Nothing works, and it reads like a routing bug for a week.
Name every template explicitly. See §6.4.

**Check each upstream's RTBH support before relying on it.** Blackhole community value, whether
they'll accept a /32 at all and RPKI-invalid handling all vary. See §9.4.

**Check RouterOS filter syntax against your build.** `bgp-large-communities includes ...`,
`set bgp-path-prepend N` and the `set bgp-large-communities ""` strip are all written from the
ROS7 rule language as documented. Property and matcher names drift between releases. Test on one
BR against a bench peer before pushing to four.

**Damping is a weaker motive than it looks.** RFC 2439 damping is off or heavily relaxed on most
modern transit networks (RIPE-580 advised against the original aggressive parameters). The real
reasons for this change: *no reconvergence churn on every home maintenance window* and *remote
sites survive a home outage*. Both good. The damping story is mostly folklore.

**Never advertise the /24 into iBGP.** Both output filters reject it explicitly. A leak sends
in-block traffic with no specific route from an ER to a BR that'll just drop it.

**The hysteresis in anchor-guard is the point.** Withdraw after 60s of *total* isolation.
Re-originate immediately. Without it one flapping adjacency reproduces the exact upstream flap this
design exists to prevent.

**The DHCP default at distance 250.** Easy to miss and it fails silently. A BR with dead transit
keeps promising your ERs a default, they keep sending it traffic, and the provider drops it at
their prefix filter because you're not announcing anymore.

**MSS clamping still lives on the ERs.** Every BR↔ER flow crosses one. **But once you add
remote-site tunnels the BRs must clamp too**, because site → BR → internet never touches an ER.
That's the day the BR forward chain stops being empty.

**The v6 clamp isn't the v4 clamp.** `wg_mtu - 60`, not `wg_mtu - 40`. MSS is what's left after
the headers and the IPv6 header is 40 bytes. Shipped wrong (both families clamped to 1320) and
caught later. The symptom would have been v6-only large-transfer stalls wherever a remote end
filters ICMPv6 PTB, with v4 perfectly healthy next to it. Derived in `derive()` and enforced in
`validate()` so it can't drift from `wg_mtu` again.

**RPKI / IRR need nothing.** Still one /24, still origin AS64500, still max-length 24. Where
inside your AS the prefix gets *originated* is invisible from outside.

**RTBH still works.** Accept the blackhole community from each upstream. A /32 nulled on one BR
propagates through the full-mesh iBGP to the others.

**Key count.** The backbone adds 6 tunnels → 12 more keypairs on top of the 32 for BR↔ER.
Generate them from a script and template the peer stanzas. Hand-copying 44 base64 keys is how you
end up with one tunnel that quietly never handshakes.

**IPv6 announces a /42, not the /40, for an *internal* reason.** Otherwise the AWS BYOIP range
falls under each BR's origination blackhole and gets dropped for in-AS traffic only. See §16.1.

**The /40 ROA at maxLength 40 makes your /42 announcement Invalid.** You need a *second* ROA for
the /42. Don't widen maxLength to fix it. And AWS needs *two* ROAs (AS14618 **and** AS16509). See
§16.4.

**IPv6 RA acceptance needs a reboot, so the deploy reboots unconditionally.** Miss it and v4 is
healthy while only v6 egress is quietly dead. See §16.6.

**Peer v6 BGP from the address the provider expects, not a tidy one.** Wrong address = SYN dropped
at the TCP layer, nothing in any log. Vultr's is EUI-64 and changes on instance rebuild. See §16.6.

**SSH keys are a build-time replace.** The templates clear all keys before importing from
`keys_url`, so a key removed at the URL is revoked on the next build. Rotating a key is a
regenerate + redeploy, not a live push. See §15.

**Pre-Shared Keys (PSK) on every tunnel.** Every WireGuard peer carries a unique `preshared-key`.
32 random bytes, base64, generated by `generate.py` and stored in `keys.json` under
`psk:<tunnel-id>`. Both ends of a tunnel share the same PSK. It's a post-quantum mitigation.
WireGuard's Noise IKpsk2 handshake mixes the PSK into key derivation, so even if someone records
today's handshakes and later breaks X25519 with a quantum computer, the symmetric PSK still
protects the session keys. Free at runtime (one extra HKDF round), no added latency, and
`--rotate-keys` regenerates them with the X25519 keypairs. The PSK **doesn't** replace the keypair.
It's a second independent secret a future attacker has to compromise too.

---

## 13. VRRP retired — BGP is the reachability and health signal

**Decision.** The home customer edge is **eBGP only** now. A firewall (`fwa`, AS65010, `.236`)
peers eBGP with *both* ERs over the transit `/29` and claims its VIPs out of the `/25`. VRRP, the
VRRP VIP (`.235`, now free), the `check-gateway=ping` `/25` static and pfSense-as-default-gateway
are all gone.

**Why.** The old model proved home was alive two ways. Both weak:

- **Inbound liveness was a ping.** `check-gateway=ping` against `.236` withdrew the `/25` when
  pfSense stopped answering ICMP. But a box can answer ping with a dead dataplane. A ping proves
  reachability, not *forwarding*. A live eBGP route proves the firewall is healthy enough to hold a
  session and is actually advertising service. Real health, not a heartbeat.
- **Failover was VRRP.** One active box owned the VIP and the standby waited. No load sharing, and
  the cutover was a VRRP election instead of a routing decision. Moving VIP claims onto eBGP gets
  you **ECMP** for free. Two firewalls advertising the same VIP at equal preference get
  load-balanced by the ERs, and losing one is just a withdrawn path. No election.

**Mechanism** (full detail in [origination.md](docs/origination.md)):

- Each ER originates the `/25` off a **blackhole `home-anchor`** (`distance=254`), just like the
  BR's `/24` anchor. `output.network=advertise` + `output.network-blackhole=no` make the anchor
  route the origination switch.
- **`home-anchor-guard`** (ER-side script, mirrors the BR `anchor-guard`) enables the anchor while
  ≥1 customer VIP is a live eBGP route and disables it when the last one withdraws. Ships
  **enabled** with the scheduler commented out. Arm it only after proving it, same discipline as
  the BR guard.
- Customer VIPs arrive as eBGP `/32`s (distance 20) and win for claimed IPs. The `/25` blackhole
  catches **unclaimed** home space and drops it at hdc so it can't loop.
- **Egress** is BGP too. Both ERs advertise a default to `fwa`
  (`output.default-originate=if-installed`), so the firewall ECMPs outbound across er1/er2 and
  drops an ER the instant that ER loses its own upstream. That's what the VRRP default gateway used
  to do. The default is the only thing `cust-out` may emit.

**The losing option we kept visible: keep VRRP for a non-BGP device at the edge.** Tempting as a
hedge. "What if I someday want a box here that doesn't speak BGP?" Rejected:

- A dumb device that can't run BGP doesn't need a VIP. It needs a gateway. Point it statically at
  **er1's transit address** (`.233`). If er1 is down, repoint it at er2. The transit path is
  **stateless** (no conntrack on transit, see the raw/notrack rules) so there's nothing to
  resynchronise on the switch. That covers the whole non-BGP case without a protocol.
- Keeping VRRP for that hypothetical means running a second redundant liveness/failover protocol
  next to BGP forever, plus burning an address on the VIP. **The static route saves the IP** (`.235`
  is free now) and removes a moving part.
- If a real non-BGP HA need ever shows up, VRRP can come back as a *local* concern on the transit
  segment without touching origination. The `/24` doesn't depend on it, so it's not worth carrying
  just in case.

**Addressing change.** `.235` (was the VRRP VIP) is freed. `.236` is now `fwa.hdc`, the eBGP
customer transit peer, not "pfSense WAN." No other addresses move.

**Validation change.** A VIP shared by two firewalls used to *require distinct* `local_pref` (a
deterministic winner). Under ECMP the default is *equal* preference (both paths installed).
Distinct `local_pref` still gives deterministic primary/backup on purpose. `generate.py` now only
rejects a **mix** of set and unset `local_pref` on a shared VIP. That quietly pairs your value
against RouterOS's default and picks a winner you didn't intend.

**Blast radius if it stays down.** Losing one ER session is invisible (the other ER holds the
VIP). A full firewall outage withdraws the `/25`, but the BRs keep announcing the `/24` and only
pull it after their 10-min no-customer timer. A brief outage never reaches the DFZ. See the
[failure matrix](#8-failure-matrix).

---

## 14. The customer grant model — enumerated VIPs vs. delegations

§13 put the customer edge on eBGP. A firewall claims space by advertising more-specifics to *both*
ERs, and the ER's inbound filter is the security boundary. A firewall gets exactly what's granted
here and **nothing else**. This section is about *how you write that grant*, because there are two
shapes and they aren't interchangeable.

**Two shapes, one primitive.** Both compile to *a prefix plus an accepted `dst-len` range*. The ER
filter never learns which shape produced it. `normalize_claims` in [generate.py](generate.py) does
the compiling.

| Shape | `topology.yml` | Means | Compiles to |
|---|---|---|---|
| **Enumerated VIP** | `allowed_vips: [203.0.113.16/32]` | This prefix, this **exact** length. Nothing else. | `dst==P && dst-len==L` |
| **Delegation** | `delegations: [{prefix: 203.0.113.0/28, max_len: 32}]` | This block, **or any more-specific down to `max_len`**. | `dst in P && dst-len>=P.len && dst-len<=max_len` |

**Why delegations, and what they beat.** The tighter model: enumerate every VIP /32. Auditable and
exactly as narrow as it looks. But it makes *the ER a change-control chokepoint for the customer*.
Every new service the firewall stands up needs a line here and a **redeploy of both ERs**. A
delegation grants a block once and gives the firewall autonomy inside it. New services down to
`max_len` need no re-render. You trade a little precision (the firewall can advertise anything
inside the block) for the firewall's independence, and `max_len` bounds exactly how much you gave
up.

- Use **enumerated VIPs** when the set is small and stable (`fwb`, one service address).
- Use a **delegation** when the firewall owns a range and will churn inside it (`fwa`).
- You can **use both** on one firewall.

**The `max_len` ceiling is the whole safety story.** Leave it out and it defaults to the family
ceiling (**32 for v4, 64 for v6**) and can never exceed it. The v6 ceiling isn't cosmetic. **A v6
LAN is a /64** and SLAAC breaks on anything longer, so a delegation allowing a /112 would grant
space the customer can't autoconfigure. A firewall that wants a single v6 service address
advertises a /128 via `allowed_vips_v6`. Between the two shapes every legit case (a LAN block, a
host route) is covered and nothing in between leaks.

**What this doesn't change.** The origination mechanism (§13) is untouched. *Any* live customer
advertisement holds the `home-anchor` up: a VIP /32, a delegated more-specific or the delegation
block itself. `home-anchor-guard` counts live customer routes and doesn't care which grant shape
produced them. Same generalisation as the BRs' "*any* customer prefix" test (§6.5). No privileged
prefix, just a set of grants, and any one of them keeps the aggregate originating.

---

## 15. SSH key management — build-time import, one source of truth

**Decision.** Router login is **key-only** and the authorized-key set is **fetched from a URL at
build time**. Not stored in the repo, not hand-managed on the router. `topology.yml` carries only
*where* to fetch and *for which user*:

```yaml
ssh:
  user:     netops
  keys_url: https://keys.example.org/sshkeys
```

`generate.py` pulls the keys fresh on every build. Each template then, for that user, creates the
user if missing (`group=full`, key-only), **removes all existing keys** and re-imports the fetched
set. Public keys aren't secrets, so the URL and username live in the committed topology. The keys
themselves never go in the repo.

**Why fetch at build time, and what it beat.**

- **Keys committed to the repo.** Safe (they're public), but then the repo is the source of truth
  for *who can log in* and rotating a key becomes a commit + review. One URL makes one endpoint the
  source of truth for every router at once. Granting or revoking access means editing that
  endpoint, and the next build enforces it everywhere.
- **Keys hand-managed on each router.** Drifts immediately and invisibly. The exact objection §10
  raises about manual config in general.
- **A runtime fetch on the router.** Rejected. A router mid-rebuild may not have a route to
  `keys_url` yet, but the machine running `generate.py` always does. Baking the keys into the
  generated `.rsc` means a router with no upstream still comes up with the right keys.

**`ssh-keys/remove` before import is required.** The import is a **replace**, not an add. A key
deleted from `keys_url` is gone from the router on the next build. Without the clear a removed key
would linger forever and "revocation" would be a lie. Declared state is the *whole* state. Same
fail-safe discipline as the anchor guards.

**The cost is on purpose.** Rotating a key needs a regenerate + redeploy, not a live push. That's
correct. It routes key changes through the same Ansible + git path as every other config change
(§10) so access is auditable and revertible.

**Management plane stays v4.** SSH is bound to `mgmt_prefix` (v4) and there's **no v6 management
hole** in the BR input filter, on purpose. Add a v6 mgmt prefix to `topology.yml` before expecting
to reach a router over v6 (§16).

---
## 16. IPv6 — dual-stack over `2001:DB8::/40`

Full addressing detail is in [docs/addressing-v6.md](docs/addressing-v6.md). The P2P offset formulas
are the v4 ones with the block base swapped, so addressing arithmetic lives in exactly one place.
This section records the *decisions*, and the ones that bite.

**Dual-stack, and v6 reuses the v4 build path instead of running a parallel one.** The generator
derives v6 tunnel /127s, loopbacks and transit from the *same* index arithmetic that drives v4. "The
v6 build path is the v4 build path with a different `ip()`." No second addressing scheme to keep in
sync.

**`prefix_v6` is the master switch.** Set it and IPv6 turns on across the generator and both
templates. `generate.py` then **refuses to render any BR without a `wan_v6` block** instead of
quietly building a v6-less border router. A half-configured router is a worse failure than a loud
one at generate time.

### 16.1 Announce a `/42`, not the allocated `/40`

ARIN allocated `2001:DB8::/40`. The BRs originate **`2001:DB8::/42`** (the first 64 /48s). No v4
counterpart (there we announce the whole /24), so `topology.yml` carries both `prefix_v6`
(allocation) and `aggregate_v6` (announcement).

The reason is **internal, not external.** Announcing the whole /40 works fine for the outside world.
AWS's BYOIP /48 is a more-specific and wins. But each BR holds the announced aggregate as a
`blackhole` at `distance=254` (the origination anchor, §2). If that anchor covered the AWS range,
traffic **from inside AS64500** to our own AWS /48s would hit the blackhole and get dropped while
the rest of the internet reached them fine via AWS. A split-brain you can only see from inside.
Announce only what we route and the AWS range drops out of our table, so in-AS traffic falls through
to the default and reaches AWS like anyone else.

**One prefix, not seven.** Carving the /40 *around* the AWS /46 would take
`/42+/42+/42+/43+/44+/45+/46`. Deaggregation for nothing. The /42 is one DFZ entry, same as the /40
was, and `00–3F` is infra + hdc + 62 sites of headroom. Everything from `40::` up is *unannounced*,
which isn't *lost*. A future block can get its own announcement. `generate.py` refuses to render if
any block in `blocks_v6` falls outside the announced aggregate. That catches someone addressing
hosts the world has no route to.

### 16.2 A `/48` per site deletes the home special case

In v4 home holds a `/25`, **half the AS**, and [origination.md](docs/origination.md) keeps having to
explain why the /25 is special. In v6 `hdc` holds one `/48` out of 256, same as every future remote
site. So the guards' "*any* customer prefix" test (§6.5) becomes truly uniform. No privileged home
prefix, just a set of site /48s, and any one holds the aggregate up. **The special case disappears
instead of being carefully handled.** Sites are allocated in order from `01` and **never reused**. A
decommissioned site's /48 stays burned because stale route objects and third-party filters outlive
your topology.

P2P links are **/127** (RFC 6164). The exact /31 analog, same reason: a /64 on a P2P link is a
ping-pong and neighbour-cache-exhaustion target. Infra is one `/60` per class so the 4th hextet's
leading nibble reads as a category label.

### 16.3 AWS BYOIP is a contiguous `/46` needing *two* ROAs

`2001:DB8:FC::/46` (four /48s) is the one place inside the /40 where the origin AS **isn't** 64500.
AWS advertises BYOIP space from **AS14618 or AS16509** depending on region. Keeping it contiguous
makes that exception one range you can state, filter and reason about. Not four scattered /48s. It
sits **outside** `aggregate_v6` on purpose and `generate.py` refuses to render if the two overlap.

**AWS needs two ROAs, one per Amazon ASN.** Authorise only one and the regions using the other come
out RPKI **Invalid**. Two ROAs for one prefix with different origins is legal. A route is Valid if
*any* ROA validates it.

### 16.4 The RPKI maxLength foot-gun

Required ROAs, and why there's **no soft-failure mode**:

| Prefix | Origin | maxLength | Why |
|---|---|---|---|
| `2001:DB8::/40` | 64500 | **40** | makes the *unannounced* rest of the /40 Invalid to hijack |
| `2001:DB8::/42` | 64500 | **42** | makes the actual announcement Valid |
| `2001:DB8:FC::/46` | **14618** | 48 | AWS BYOIP, both required |
| `2001:DB8:FC::/46` | **16509** | 48 | AWS BYOIP, both required |

**A /40 ROA at maxLength 40 makes the /42 announcement Invalid** (RFC 6811). The space is *covered*
by a ROA but *validated* by none, and validating networks **drop Invalid where they'd accept
Unknown**. So the /42 needs its own ROA before it's announced. Keeping the /40 ROA too isn't
redundant. It makes every unannounced /48 Invalid for anyone else to originate instead of just
Unknown. **Don't widen maxLength to "fix" the Invalids.** Tight maxLength is the defence (same lesson
as the v4 /24, §9.4). And since the /40 ROA already *covers* the AWS range with origin 64500, a
missing or wrong-ASN AWS ROA makes those /48s **Invalid, not Unknown**. Get the AWS ROAs right
**before** AWS starts advertising, and create them as you onboard each /48. Not up front.

### 16.5 Protocol decisions: separate everything

**iBGP: separate sessions over v6 loopbacks**, not the v6 AFI on the existing v4 sessions. Double the
sessions. What it buys: trivial next-hop-self (no RFC 5549 next-hop gymnastics) and **separate
failure domains**. A v6 policy mistake can't take v4 down with it. Every router has a v6 loopback
(`::b1`, `::e1`, …) so these sessions have a canonical endpoint.

**OSPFv3 as a separate instance** (ROS7 runs it next to OSPFv2 with no interaction). Adjacencies form
on link-locals, so the protocol doesn't **need** the /127 GUAs. They're there for traceroute
legibility and DNS, the same trade v4 already makes. WAN preference stays in OSPF cost (`wan1`=10,
`wan2`=100), never BGP. And **don't let the two IGPs disagree.** A v4 path and a v6 path preferring
different WANs make failures asymmetric and debugging miserable.

### 16.6 Two provider gotchas that fail *silently*

**RA acceptance costs a reboot on every deploy. On every router.** RouterOS doesn't apply
`/ipv6/settings accept-router-advertisements` until a reboot, and `reset-configuration` restores the
factory default and reboots *before* `run-after-reset` sets our value. Not just Vultr's `=yes`
(RA-learned default). The factory default is `yes-if-forwarding-disabled`, so `br2` and both ERs
setting `=no` change it just as much. That's why `ansible/deploy.yml` **reboots unconditionally**
after any applied config and checks for an active `::/0` afterwards on the `gateway: ra` routers.
Skip it and the failure is quiet. v4 is perfectly healthy and only IPv6 egress is dead.

**Ask the provider which address they peer with. Owning the /64 isn't choosing it.** Both providers
constrain it. HostHatch peers only with `::179`. Vultr only with the address assigned to the
*instance*, an **EUI-64 value derived from the NIC MAC that changes if the instance is rebuilt**. Get
it wrong and it fails at the **TCP layer with no signal**. SYN dropped, no RST, no ICMP unreachable,
nothing in the BGP log. The session just never appears. The tell is `/ipv6/firewall/connection`,
where the outbound flow sits at `tcp-state=syn-sent`, `repl-packets=0` forever. Diagnosed
2026-07-21. Cost half a day. The exact values live in `topology.yml` next to each BR's `wan_v6`
block with the reasoning inline. **Don't "tidy" them to `::1`.**

### 16.7 Status

**Implemented and generating.** Not done yet, each one a deliberate stop: the ROAs (nothing is
announced until the /40 ROA exists), the ARIN reverse-zone delegation + PTR push, the provider WAN
PTRs (set in the panels, not ours to self-manage). And `anchor-guard` **stays unarmed**. With
`sites: []` the "any customer prefix" generalisation has nothing to generalise over, so arming it
now would let a long home outage withdraw the aggregate from the DFZ.

---

## 17. BR WAN: static on ether1, default gateway static, never DHCP

Decided 2026-07-20. The BRs' provider uplink on `ether1` is now a **static address + static default
route**. DHCP is gone from the BR WAN path entirely. Two bugs and one clean-up drove this.

### 17.1 The default must be static, not DHCP- or BGP-learned

The old BR template let the DHCP client install the default (`default-route-distance=30`). Its
`static_default` branch did a `/ip/route set [find … && static]` on a route **nothing ever added**.
A silent no-op. So in practice the installed fallback default was the DHCP one and the effective
default resolved via the provider/eBGP path.

The problem: a DHCP- or BGP-learned default **can't be cleanly re-originated into the iBGP full
mesh**. A BR must hand a default to the *ERs* (`default-originate=if-installed` on ER-facing
sessions) but **never to a sibling BR**. A sibling default points that BR's tunnel-endpoint route
back into the tunnel (permanent flap) and makes it egress through the sibling's transit, where its
own-sourced packets die at the sibling upstream's BCP38 filter. A **static** default at
`distance=30` is deterministic and installs unconditionally (so `if-installed` and `default-guard`
behave). It still **loses to the eBGP-learned default (20)** when a real upstream default is there,
and still **beats an iBGP default (200)** from a sibling.

- **Chosen:** `/ip/route add dst-address=0.0.0.0/0 gateway=<wan_gateway> distance=30`.
- **Over:** DHCP `default-route-distance=30` (non-deterministic, races the static one, re-originates
  badly) and eBGP-only (no fallback when the upstream session is down).

### 17.2 ether1 is a static address, not a dhcp-client

Going prescriptive means DHCP no longer supplies the WAN **address** either. `topology.yml` gains a
per-BR **`wan_prefix`** (Vultr `/23`, HostHatch `/24`. `wan_via_dhcp` is deleted) and the template
renders `/ip/address add address=<wan_address>/<wan_prefix> interface=ether1`.

That trades a self-configuring address for a **lockout risk**. A wrong prefix (or a gateway outside
the subnet) and the box comes back from a `reset-configuration` reachable only via provider console.
Accepted on purpose. The rollout is gated per device (`ansible/deploy.yml` stops on the first box
that doesn't come back) and BR redundancy means one static mistake never costs full connectivity.
`generate.py` **validates hard** as the guard: `wan_prefix` must be an int in 1..32 and `wan_gateway`
must fall inside `wan_address/wan_prefix`. It can't catch a prefix that's wrong *and* still contains
the gateway (`/22` vs `/23`). That bit's on the operator.

### 17.3 "No DHCP on ether1" is enforced in Ansible, scoped to BRs

`reset-configuration no-defaults=yes` already means no factory dhcp-client exists. But a box reset
*without* that flag would keep one, and it would fight the static address and inject a rogue
default. So `ansible/deploy.yml` runs an explicit `/ip/dhcp-client remove [find interface=ether1]`
after every verified deploy. That's the **hard** gate. The template alone isn't enough.

It's **BR-only on purpose** (`router_role: br|er` in `inventory.yml`, `when: router_role |
default('br') == 'br'`). Unknown hosts default to `br`, so protection is the safe default. The ERs
are exempt because their WANs are data-driven (`address` present ⇒ static, absent ⇒ dhcp-client) and
home is expected to **move off statics onto the BGP block**, at which point an ER may legitimately
DHCP `ether1`. DHCP on `ether2`+ was never affected. That's exactly how the ERs' `wan2` works today.

- **Chosen:** BR-scoped purge via `router_role`.
- **Over:** a blanket host-agnostic purge (would quietly strip a future ER's ether1 dhcp-client) and
  a template-only static (no defence against a reset without `no-defaults`).

---

## 18. Rollout — Ansible reset-and-restore

`ansible/deploy.yml` pushes each generated `out/<fqdn>.rsc` onto its router. It's the operational
half of "**Ansible + git, not a BGP-signalled RPC**" (§10). The config is a pure function of
`topology.yml` and this is how that function reaches the hardware. Full operator guidance is in
[ansible/README.md](ansible/README.md). This records why the playbook looks the way it does.

### 18.1 Reset-and-restore, not incremental import

The apply is **destructive**. `scp` the `.rsc` up, then
`/system/reset-configuration no-defaults=yes skip-backup=yes keep-users=yes run-after-reset=<fqdn>.rsc`.
The router wipes itself and replays the generated build script from a clean slate on every deploy.

- **Chosen:** wipe + replay a deterministic `add`-only build script.
- **Over:** incremental `/import` of a delta (piles up state the source of truth never described,
  the exact drift §10 exists to kill), and a true declarative diff against a live `/export` (not
  practical. An `add`-only script isn't comparable to a live export without a fragile normalization
  pass, and getting that wrong is worse than not having it).

The whole model depends on the generator being **deterministic**. Same `topology.yml` →
byte-identical `.rsc`. That's what makes both the replay and the change detection below trustworthy.

### 18.2 One router at a time, alternating BR/ER, behind a manual gate

`serial: 1` + `order: inventory` pins the sequence **br1 → er1 → br2 → er2**. The alternation is the
point. One border router **and** one edge router stay up at every step, so the `/24` anchor and the
`/25` are never both dark at once. Same-role-first (both BRs, then both ERs) would leave a window with
no live edge.

A **manual confirmation gate** comes before each router, and the playbook is *not* fully unattended.
On purpose. The reset drops all connectivity. If the generated script errors halfway, the box is
reachable **only via provider console/VNC** until fixed. So a human confirms the previous box
actually recovered, console already open, before wiping the next one. `any_errors_fatal: true`
stops the whole run on the first failure instead of marching on through the rest of the fleet.

### 18.3 Idempotence is a fingerprint on the device, not a live diff

"Leave it alone if nothing changed" works like Terraform's **state**, not its plan. After a
*verified* deploy the playbook stashes `sha256(applied .rsc)` on the router as `<fqdn>.applied`. The
next run regenerates the config, compares and **skips the device with no reboot if the hashes
match**. The fingerprint file survives `reset-configuration` for the same reason `run-after-reset`
works. Files persist across the wipe.

Know where it stops so nobody trusts it too far:

- It tracks **"did the intended config change since we last pushed"**, not "does the live box
  match". A hand-edit on the router still fingerprints as unchanged. Which is exactly the drift §10
  tells you not to create.
- A device provisioned **outside this tool** has no fingerprint. It reads as changed and gets
  offered for redeploy (a safe false positive).
- The fingerprint is written **only after the identity check passes**. A failed or half-applied
  deploy is never recorded and the next run still sees it as changed. Failing closed, again.

### 18.4 Verification is down → up → identity — a smoke test, not a health check

After the reset the playbook waits for SSH to go **down** (proof the reset took and wasn't a silent
no-op), then **back up** (proof the script re-created SSH-on-mgmt), then reads `/system/identity`
back and asserts it matches. That catches a lockout or a half-applied config instead of assuming
success. But it's **not** a routing health check. Checking BGP sessions, OSPF adjacencies and the
anchor between gates stays the operator's job. The gate prompt says so.

### 18.5 The second reboot is unconditional — it implements §16.6

Every router that gets config applied **reboots twice**. This is how the IPv6-RA decision in §16.6
gets implemented. `reset-configuration` restores `accept-router-advertisements` to the factory
default and reboots *before* our `.rsc` sets the value, so what we write never takes effect without
a second reboot. **Unconditional**, because every one of our routers moves that setting off the
factory default (br1 to `=yes`, br2 and both ERs to `=no`). And keeping it unconditional means any
future setting that needs a reboot is already covered. The cost is bounded. Unchanged devices ended
the play back in §18.3 and never get touched. A device that gets here was being wiped and rebooted
anyway. The follow-up `::/0` assertion is scoped to `gateway: ra` routers **only** (see §16.6).
That's the one place the RA is the actual source of the default, so it's the only place the check
tells you anything.

### 18.6 The control node must source from `mgmt_prefix`

SSH is source-filtered to `mgmt_prefix` (`192.0.2.176/28`) in both templates, so the playbook only
works run **from the home site**. From anywhere else every connection times out (the preflight
catches that early instead of mid-reset). Two SSH options are non-negotiable and set in
`inventory.yml`. `StrictHostKeyChecking=no` + `UserKnownHostsFile=/dev/null`, because
`reset-configuration` **regenerates the router host key** and a pinned `known_hosts` entry would
break every post-reset reconnect. And `BatchMode=yes`, so a missing key fails fast instead of hanging
on a password prompt mid-reboot, which is exactly where an unattended rollout would wedge. Auth is
SSH keys (§15), kept across the reset by `keep-users=yes`.

---
## 19. BFD — sub-second liveness under OSPF

§7 establishes that **OSPF hellos are the only liveness detector in this network** because a
WireGuard interface has no carrier and never goes down on its own. Still true. What §7 didn't cover
is *how fast*. OSPF's floor is `dead-interval`: **20 s** on the backbone and wan1, **40 s** on wan2
and **40 s** (the RouterOS default) on the er1↔er2 interconnect, which never had explicit timers.
Twenty seconds of forwarding into a dead tunnel is a long outage for a failure the network is
otherwise built to survive.

BFD (RFC 5880) is a hello protocol that does *only* the liveness job. No adjacency, no LSA flooding,
no SPF run. So it can run at intervals OSPF can't and hand OSPF the verdict. Detection drops from tens
of seconds to hundreds of milliseconds. Configured in `/routing/bfd/configuration`, requested with
`use-bfd=yes` on the OSPF interface-templates.

### 19.1 BFD is additive — the OSPF timers do not move

Every `hello-interval`/`dead-interval` in both templates is byte-for-byte what it was. It's tempting
to relax them once BFD carries the load. Don't, because of the failure mode. **If a BFD session never
establishes, a network that kept its OSPF timers degrades to exactly yesterday's behaviour. One that
relaxed them degrades to something slower than it's ever been tested at.** The saving would've been a
handful of packets per second. Not worth it.

It's also what makes the feature safe to arm at all. Worst case is "no faster than before".

### 19.2 One interval per link class, and the numbers are about the media

The timers mirror `ospf_cost`. Same four classes, same file, same reasoning. `detect = interval ×
multiplier`:

| Class | Interval × mult | Detects | Was |
|---|---|---|---|
| `backbone` | 200 ms × 3 | ~600 ms | 20 s |
| `wan1` | 300 ms × 4 | ~1.2 s | 20 s |
| `wan2` | 1 s × 5 | ~5 s | 40 s |
| `er_xc` | 100 ms × 3 | ~300 ms | 40 s |

**The backbone isn't at 100 ms on purpose.** Both BRs are CHR guests on shared VPS hosts (§17,
docs/chr-vps-guide.md). A hypervisor descheduling a vCPU for a few hundred milliseconds is normal
there, not a fault, and 300 ms detection would turn it into a backbone adjacency flap. 600 ms still
beats 20 s by 33×. The extra 300 ms isn't worth a new failure mode.

**wan2 is the slowest on purpose**, for the same reason its OSPF timers are already loose (§7.1).
CGNAT'd 5G. Aggressive BFD there detects mobile jitter, and detecting jitter is worse than detecting
a failure late. An adjacency that flaps every few minutes *causes* outages. 5 s vs 40 s is still 8×.

**`er_xc` gains the most and it's the least obvious.** A pulled interconnect cable drops carrier and
tears OSPF instantly, so BFD looks pointless. It isn't. BFD covers carrier up with forwarding down: a
live-but-wedged sibling ER, or a switch between them. That link sat on the 40 s default and is now
the fastest in the network.

`generate.py` rejects any class detecting faster than ~50 ms. Below that these boxes are measuring
their own scheduling noise.

### 19.3 Default-deny is the security property, and the transit forbid is defence in depth

RouterOS forbids BFD on every interface not listed in `/routing/bfd/configuration`. Good default and
it does real work here. A BR's `ether1` faces the upstream, an eBGP peer that must never negotiate BFD
with us, and it's excluded by saying nothing about it.

The ERs carried an explicit `forbid-bfd=yes` on the customer transit interface, placed first (entries
are order-sensitive, first match wins), for as long as nothing on that segment used BFD. Redundant
even then. It was there because that segment is the **one place in this AS where untrusted BGP
speakers live**: the customer firewalls (§13, §14). The redundancy stops being redundant the moment
someone adds a broader allow rule. Same instinct as the terminal `reject` on every customer filter
chain.

**§19.7 replaces that entry with a permit.** "We deleted the deny rule on the untrusted segment" is
the wrong summary of what that costs. See §19.7.2.

### 19.4 Two families, two sessions — not a choice, and the one place it costs something

OSPFv3 neighbours are link-local IPv6 addresses so each link ends up with an independent v4 and v6
BFD session. No extra config needed. `/routing/bfd/configuration` matches on **interface**, not
address family, so both sessions inherit the same class timers. The same property §16.5 relies on for
the costs. The two families must fail identically or every failure gets debugged twice.

**The obvious economy (one BFD session over the v6 link-local feeding both instances) isn't
configurable, here or anywhere.** A BFD client registers for a session to *its own* neighbour address
and sessions are keyed on (interface, local address, remote address, family). OSPFv2's neighbour is
the v4 /31. OSPFv3's is the link-local. Nothing on the interface-template or in
`/routing/bfd/configuration` says "OSPFv2, take your verdict from the v6 session on this interface."
Other platforms do share sessions, but only among clients on the same interface **and family**
(OSPFv2 and BGP and static sharing one v4 session). Never across families. So the single-session
design comes down to dropping `use-bfd` from the `core` instance, which puts IPv4 back on
`dead-interval`. 20 s and 40 s, the exact numbers this section exists to delete. Two sessions is the
only shape that covers both families.

It's also defensible on its own terms, and the fate-sharing intuition argues the other way, so here's
the case. Both families ride one WireGuard transport, so a dead tunnel kills both and the second
session tells you nothing. True for tunnel death. Not for the failures above the tunnel, and two of
those are per-family *by construction* here. `allowed-address` is a cryptographic routing gate
applied per family (the `::/0` note in `br.rsc.j2`), and the inverse is just as easy: a peer that
loses `0.0.0.0/0` silently discards v4 while v6 stays healthy. And `/ip/firewall` and
`/ipv6/firewall` are two independent rule sets, so a one-family mistake is a routine error here, not
an exotic one. Either way a v6-only session would hold the OSPFv2 adjacency up over a tunnel dropping
v4 on the floor. These are faults a deploy introduces, not runtime ones, so discount them
accordingly. But they're exactly the faults where per-family detection is the only detection.

**What it costs isn't packets.** Doubling 5 pps on the backbone is nothing. The cost is that two
sessions run on independent timers, so a marginal link can tear one family's adjacency and not the
other. That's the asymmetric v4/v6 routing the byte-identical costs in §16.5 exist to prevent,
arriving through a different door. It's bounded. If the failure is real the other family follows
within its own dead-interval. Under *jitter* rather than failure it isn't, because one family flaps
and the other doesn't. **wan2 is where that lives.** CGNAT'd 5G, the one class whose timers are
already loose (§19.2) because noise is expected there. If a split-family flap ever shows up, that's
the link. The fix is slower wan2 BFD timers, not a second look at the session count.

Monitoring follows. The expected count is **one session per family per adjacency** (§11's 14 per BR)
and *both* members of a pair up is healthy. One up and one down is a per-family fault, not a BFD
fault. Look at `allowed-address` and the v6 firewall before touching anything in `/routing/bfd`.

### 19.5 Two switches, two passes — the rollout is the risky part

`bfd.configure` renders the configuration entries. `bfd.use_ospf` puts `use-bfd=yes` on the OSPF
templates. They're separate because **a config entry only permits a session, it never starts one**,
which makes pass 1 provably inert.

Why bother: §18.2. `deploy.yml` applies one router at a time behind a manual gate, so for a long
window half the AS has the new config and half doesn't. Arm both switches at once and br1 comes back
asking for BFD from an er2 that still forbids it. An OSPF adjacency holding a permanently-down BFD
session. Precisely the flap this feature exists to prevent. So:

- **pass 1**: `configure: true`, `use_ospf: false`, deploy everywhere. Nothing observable changes.
- **pass 2**: `use_ospf: true`, deploy everywhere. Sessions come up.

`generate.py` refuses to render `use_ospf: true` with `configure: false`. That combination is one
file-edit away and would arm every tunnel against a menu that permits nothing.

Shipping with `use_ospf: false` follows the `anchor-guard` precedent (§9). The mechanism lands
complete and inert. Arming it is a separate, deliberate act once the operator has seen it work.

### 19.6 What did not change, and one thing to reconsider later

**No firewall rules.** BFD is UDP/3784 (single-hop). Every interface it runs on is already covered by
`in-interface-list=tunnels` or the explicit interconnect accept, in both families.

**No BGP.** `use-bfd` also exists on `/routing/bgp/connection` and the obvious next candidate is the
ER↔firewall eBGP sessions, where it'd cut VIP failover from the BGP hold time to sub-second. Not done
on purpose. Those peers are customer-controlled boxes. Nobody here has tested what RouterOS does when
a BGP connection requests BFD the far end won't answer. And the guards in §9/§13 already key off
route presence, not the session alone. Revisit when there's a firewall whose BFD support has actually
been verified.

> **Superseded by §19.7.** pfSense runs FRR, FRR has `bfdd`, and that's the verified far end this
> paragraph was waiting for. The reservation wasn't wrong though. It became the shape of the
> feature: the flag is **per firewall**, not global, because "the far end answers" is a fact about one
> box and not about the segment.

**The guard timers are unchanged.** `anchor-guard`'s isolation counter still needs 6 × 10 s of
consecutive failure. Faster detection means the countdown *starts* sooner, not that it should be
shorter. The hysteresis in §9 exists so a flapping link isn't a DFZ event, and BFD makes flaps easier
to have, not harder.

### 19.7 BFD on the customer transit segment — the last slow detector

§19.6 left BGP out and named the condition for coming back: a firewall whose BFD support has actually
been verified. pfSense's routing is FRR, FRR ships `bfdd` and enabling it is a package and two
checkboxes. So here we are.

**It closes the biggest gap left in the network.** Everything else in §19 went onto tunnels that
already had a 20–40 s detector. The ER↔firewall sessions never had one. They run on the RouterOS
default BGP hold time, **3 minutes**. For those three minutes an ER holds a VIP `/32` pointed at a
firewall that's gone, keeps advertising it to its sibling over the interconnect and keeps the `/25`
home-anchor originated on the strength of a route that leads nowhere. `home-anchor-guard` (§13) isn't
a second opinion here. It keys off *route presence* and the route is present for all three minutes.
Nothing notices sooner because nothing was watching. BFD at 300 ms × 3 makes it **~900 ms**.

It bites hardest in the case the firewalls exist for. Two firewalls advertising the same VIP is the
failover mechanism (§14), and until the dead one's session drops there's no failover. The ERs ECMP
half the traffic into a black hole. Fast detection is the whole point of having two.

#### 19.7.1 A third switch, because it is a different menu with a different far end

`bfd.customer` in `topology.yml` renders the transit interface's `/routing/bfd/configuration` entry
as a **permit with timers** instead of `forbid-bfd=yes`. A per-firewall `bfd: true` puts
`use-bfd=yes` on that firewall's two `/routing/bgp/connection` entries. Same split as
`configure`/`use_ospf` for the same reason: **an entry permits, a client asks**, and they deploy in
that order.

It's *not* folded into `bfd.links` on purpose. That table mirrors `ospf_cost` class for class. This
segment carries no OSPF at all. The transit interface is `passive` in both instances because an OSPF
adjacency with a customer would hand them the internal topology. A BGP-only timer in a table whose
invariant is "one entry per OSPF cost class" breaks the one property that makes the table checkable.
`generate.py` enforces exactly that: `bfd.links` must equal `ospf_cost`, no more and no less.

**300 ms × 3, not the 100 ms the er1↔er2 wire runs at.** Both ends of the interconnect are RouterOS
forwarding in kernel. Here the far end is FRR's `bfdd`, an ordinary userspace process on a
general-purpose OS with a stateful packet filter in front of it, on hardware also doing the
household's NAT, IDS and VPN. A firewall under load isn't a firewall that's down. The failure this
must not produce is a VIP that withdraws every time someone starts a big download. 300 ms is also
FRR's own default so neither end needs tuning to agree.

#### 19.7.2 What replacing the forbid rule actually costs

§19.3 called the transit `forbid-bfd=yes` defence in depth on the one segment with untrusted speakers.
Swapping it for a permit really does narrow that. The honest accounting:

- **What still holds.** An entry only *permits*. RouterOS creates a session when a local client
  registers for one, and the only BFD client on this segment is `/routing/bgp/connection`. One per
  firewall, each with `use-bfd=yes` only if that firewall was flagged. **An unflagged firewall gets
  no session no matter what it sends us**, and neither does a machine that isn't a configured peer.
  The gate moved from the interface to the client list. It didn't open.
- **What's genuinely weaker.** The entry matches on *interface* so it covers every speaker on the
  segment, not just the two addresses that need it. Add a BFD client on that interface later and
  nothing stops it. Exactly the "future broad allow-rule" §19.3 was written against, coming from the
  other direction.
- **The tightening we didn't take.** RouterOS 7's BFD configuration is documented as matching on
  neighbour address as well as interface, which would scope the permit to the two flagged firewalls
  exactly. Not used because *the property name hasn't been confirmed on a live box in the version
  this fleet runs*, and `deploy.yml` imports **after** `reset-configuration`. A rejected line doesn't
  fail a line. It leaves the ER with no routing config below it (§26.1). Same discipline as
  `bgp_multipath`. Confirm the spelling on one ER, then narrow it. One-line template change.
- **No firewall rules changed.** BFD is UDP/3784 single-hop and the ER input chain already accepts
  the transit interface wholesale in both families. Which is also why a permissive segment isn't new
  information. Anything on it could already reach the router.

#### 19.7.3 Per firewall, and the rollout order is inverted from §19.5

The flag is per firewall because **the far end isn't ours**. §19.6's reservation (untested RouterOS
behaviour when a BGP connection asks for BFD that nothing answers) is still untested. The mitigation
is to never be in that state. Flag a firewall only after `bfdd` runs on it.

That flips §19.5's order. There both ends were routers this build writes, so the safe order was
config everywhere, then arm everywhere. Here one end is a box someone else configures:

1. `bfd.customer` set, `bfd: false` everywhere → deploy **both** ERs. The transit interface now
   permits BFD. Nothing on the wire changes. `/routing/bfd/session/print` is unchanged.
2. On the firewall: install FRR's BFD and attach it to **one** ER neighbour, leaving the ER side
   alone. The firewall now asks. The ER permits but has no client registered, so no session forms.
   **This step has an unknown in it**, the mirror of §19.6's: does FRR hold a BGP session down while
   a configured BFD session has never come up? One neighbour at a time keeps the unknown cheap. If
   that session drops, the other ER still carries the VIPs and the fix is unticking one box. Check
   BGP's still up, then do the second ER.
3. `bfd: true` for **that one firewall** → rebuild, deploy the ERs. Sessions come up.
4. Watch it through a real failure before flagging the second firewall.

Step 4 is the point of the per-firewall flag. While fwa is the experiment, fwb holds the same VIPs on
the 3-minute hold time. The behaviour this network has run all along.

`generate.py` refuses `bfd: true` without `bfd.customer` (the ER would ask for a session its own
interface forbids). It refuses `bfd.customer` without `configure` (the menu isn't rendered at all).
And it refuses `bfd: true` on a firewall whose *own config this build generates* unless that renderer
emits a BFD stanza. `unifi` doesn't today. Rendering both ends from one grant (§27) is worth nothing
if the two ends can disagree about whether there's a session between them.

#### 19.7.4 What to expect on the wire

Two sessions per flagged firewall per ER, for the §19.4 reason. The v4 and v6 eBGP sessions are
separate, sessions are keyed on family and the interface-matched entry gives both the same timers with
nothing extra written. A fully-armed fwa adds **4** sessions across the pair, and the ER count
becomes adjacency-derived plus two per flagged firewall.

`use-bfd` on `/routing/bgp/connection` is the one property here not yet exercised on this fleet.
**Verify it on a live ER before the first deploy.** `deploy.yml` imports after a wipe, so a rejected
line isn't a failed line. It's an ER with no BGP (§26.1):

```
/routing/bgp/connection set [find name=cust-fwa] use-bfd=yes
/routing/bgp/connection print detail where name=cust-fwa
/routing/bgp/connection set [find name=cust-fwa] !use-bfd
```

---

## 20. The ER's DHCP WAN default: `default-route-tables`, not a `script=`

An ER's WANs are data-driven. `address` present in `topology.yml` ⇒ static, absent ⇒ dhcp-client
(§17.3). Today er1/er2 wan1 is static and **wan2 (ether2, CGNAT'd 5G) is DHCP**. Either way the
lease's default gateway has to land in the per-WAN table `via-wan2` and **nowhere else**. The `via-*`
tables exist only so the `chain=output` mangle rules can pin each WireGuard outer flow to a specific
WAN (§7). An ER's real egress default is the iBGP one from the BRs. A DHCP default in `main` at
distance 1 would beat it and quietly steal customer egress, the same failure §17.2 purges factory
clients to avoid.

The original version was `add-default-route=no` plus a `script=` that removed and re-added the route
by hand on each bind. **It didn't work.** Lease up, client bound, no route in `via-wan2`. The gateway
in a dhcp-client script is the RouterOS variable `$"gateway-address"`, and reaching it from a quoted
`script=` inside a Jinja template inside a `.rsc` file means escaping the `$` through three layers.
The template's `\\\$\"gateway-address\"` didn't survive `/import`. The script existed on the device
and ran on every bind so nothing looked broken from outside. It just resolved the gateway to nothing
and added no route.

### 20.1 The fix is a built-in that already does exactly this

```
/ip/dhcp-client add interface=ether2 default-route-tables=via-wan2 \
    use-peer-dns=no use-peer-ntp=no comment="wan2"
```

`default-route-tables` names the table(s) the lease's default goes into. `add-default-route` is
dropped. The parameter *is* the instruction to install one, and naming only `via-wan2` keeps it out of
`main`, which was the whole point of `add-default-route=no`.

What you get is **lifecycle**. The client owns the route. It appears on bind and is withdrawn on
release, expiry or link loss, with no reconciliation logic of ours to get wrong. The script had to
hand-roll that (hence the `remove [find ...]` before every add) and had a window where a stale
default outlived a dead lease. `use-peer-dns=no` / `use-peer-ntp=no` are unchanged. A CGNAT'd mobile
carrier doesn't get to configure this router's resolvers.

### 20.2 `/routing/table` moved above the WAN block

RouterOS resolves the table name in `default-route-tables` when the dhcp-client is **added**, and
`/import` is strictly ordered. The `via-*` tables were declared with the mangle rules, ~70 lines below
the WANs. Fine for the old script (it only referenced the table at bind time, long after import) and
wrong the moment the client itself names it. The `/routing/table` block now sits right before the
WANs. The mangle rules that steer traffic *into* those tables stayed put.

You can't see this ordering dependency in a diff and it only bites on a clean `/import`. Which, per
§18.1, is the only way this network ever gets configured.

### 20.3 What this does not change

**Static WANs are untouched.** A WAN with an `address` still gets its default from the explicit
`/ip/route add ... routing-table=via-wan1` (gated on `w.gateway is defined`), and the BR-public `/32`
management routes are still static-only. A DHCP WAN has no `w.gateway` so it contributes no `/32`.
Reaching the BRs over a DHCP WAN rides the tunnel, not a main-table static.

**The purge stays.** `/ip/dhcp-client remove [find interface=...]` still runs per-WAN before the add.
Same reason as §17.2. A factory client on a reset box would carry `add-default-route=yes` into
`main`, and the template (unlike the BR-only Ansible task) is the only thing that knows which
interface is meant to be which.
## 21. RouterOS 7.19 turned `/ip/service` into a port table — `mgmt-refresh` broke on it

*In which a minor version bump eats a script and nobody says sorry.*

First hand-run of `mgmt-refresh` (the `enabled: false` pass-1 discipline set out at `mgmt_refresh` in
`topology.yml`) did the address-list half correctly and then put this in the log:

```
failure: this is configured elsewhere (/ip/service/set *0 = telnet) (/ip/service/set; line 129)
```

**RouterOS 7.19 changed what `/ip/service` is.** It stopped being the eight static services and
became a view over every listening TCP/UDP port on the box. Live connections, container ports, the
`winbox` and `ssh` listeners themselves, all surfaced as `D`-flagged dynamic rows that **share the
NAME of the real service**. The fleet runs 7.19.4 (`docs/chr-vps-guide.md`) so every router has them.

So the script's `[find name=winbox]` stopped meaning "the winbox service" and started matching the
static row *plus* a dynamic one. `set` on a dynamic row fails. A dynamic row reflects a socket. It
isn't a configuration object.

### 21.1 Both halves of that error message lie

**The id isn't the row it choked on.** `*0` gets resolved against the *static* table for display, so
the message names `telnet`. A service the script never touches and which is `disabled=yes` three
lines into every config we ship. Debug this from the log alone and you start in the wrong place.

**The line number points one line past where you'd guess.** Script body lines count from the newline
right after `source={`, which puts 129 on the **winbox** `set`, not the `ssh` one above it. The ssh
ACL had already been written. Read it as "ssh failed" and you've got the device's state backwards.

### 21.2 The damage was not the stale ACL

The error was uncaught so it aborted the script. And the abort landed **between the address-list
update and the SSH key refresh**. Worst possible spot. Addresses current, keys never refreshed even
once, and the only evidence a log line naming the wrong service.

It couldn't converge either. `$mrSvcAcl` is only assigned *after* the ACL write, so every run redid
the same work, hit the same error and cached nothing. Including the runs where the endpoint really
had changed.

### 21.3 The fix, and why it logs instead of aborting

```
:local svcOk true
:do {
  /ip/service/set [find where !dynamic name="ssh"] address=$svc
  /ip/service/set [find where !dynamic name="winbox"] address=$svc
} on-error={
  :set svcOk false
  :log error ("mgmt-refresh: service ACL set FAILED - address-list is current, ACL is STALE, keys still refreshed")
}
:if ($svcOk) do={ :set mrSvcAcl $svc ; :log warning ("mgmt-refresh: service ACL -> $svc") }
```

`!dynamic` is the correctness fix. The `:do`/`on-error` is the *design* fix, and it's deliberate.
This script's whole premise is that no partial failure may cost you access (guards 1–4, stated in the
`_mgmt.j2` header above the script). A failed ACL write deserves a loud log. It doesn't deserve to
silently kill the half of the script that keeps you able to log in. `$mrSvcAcl` is set only on
success, so a failed run retries next tick instead of caching a value it never applied.

### 21.4 What this does not change

**The deploy-time `/ip/service` block is untouched.** The top of `_mgmt.j2` still uses positional
`set ssh …` / `set winbox …` inside the `/ip/service` menu. Different resolution path from `find`,
and *proven* on 7.19.4 because the fleet imported through it. Rewriting a working line on the one path
where failure lands **after** `reset-configuration` wiped the box is the worse trade. A syntax slip
there fails at line 19 instead of line 129, with nobody left to log in and fix it. If it ever does
get ambiguous, `/ip/service/print where name=winbox` showing a second `D` row is the tell.

**Assume this class of bug comes back.** Any `[find …]` against a menu MikroTik later fills with
dynamic rows has the same shape. `/system/ntp/client/servers` (§22) already works this way: a static
list plus dynamically discovered entries in one table.

## 22. The edge resolves through public anycast, never through internal DNS

`mgmt-refresh` failing on a fresh CHR turned up a gap under it. **No template ever set
`/ip/dns servers=`.** The routers shipped with no resolvers at all and had to be fixed by hand before
the fetch would run.

It stayed invisible because guard 1 works. A router with no resolver can't resolve
`mgmt_prefixes_url`, the fetch fails and the script correctly changes nothing. So a completely
unconfigured resolver shows up as *silence*, not breakage. Same trap as the empty `/certificate`
store already noted at `mgmt_refresh` in `topology.yml`.

### 22.1 Public resolvers on ERs too, not pfSense

The rule: **nothing a router needs to boot may sit behind that router.** The edge is how you reach
everything else, so it can't depend on anything reachable only through itself. That applies to the
ERs as much as the BRs. Both get the same public anycast list and neither resolves through pfSense or
across a tunnel. `_mgmt.j2` renders byte-identical on all four.

For the record, the feared circular dependency **didn't actually exist** for the endpoint itself.
`a.example.net` is public in Route 53 (`ns-*.awsdns-*`) and resolves to AWS addresses, so the path
was always router → public resolver → Route 53 with nothing internal in it. The rule above is still
right. It just doesn't hold anything up for *this* name.

### 22.2 Root-server recursion was considered and rejected

RouterOS can't do it. `/ip/dns` is a **forwarding cache with no root hints and no recursion**. It
needs upstreams. The only way to a real recursive resolver on a CHR is a container running unbound.
That means enabling a container runtime (a `device-mode` change plus reboot) and then operating a
resolver, all inside the dependency chain of break-glass access. `mgmt-refresh` exists so restoring
access doesn't need a config push. Making it depend on a container we also have to maintain inverts
that. Anycast wins.

### 22.3 The list, and why each part of it

```
/ip/dns
set servers=1.1.1.1,8.8.8.8,9.9.9.10,2606:4700:4700::1111,2001:4860:4860::8888
set allow-remote-requests=no
```

**Two operators, two anycast clouds, dual-stack.** A v4-only list would let a bad day on v4 transit
take name resolution with it, on a fleet that's dual-stack on purpose (§16).

**`9.9.9.10`, not `9.9.9.9`.** `.9` applies a threat feed. `.10` is unfiltered. A false positive
there would `NXDOMAIN` `mgmt_prefixes_url`, the one name that has to resolve at the exact moment
everything else is already broken. Blocklisting is a liability on infrastructure.

**`allow-remote-requests=no` explicitly, not just by default.** The input chains drop UDP/53 from the
WAN. But they also `accept src-address-list=mgmt` wholesale, so the firewall is the only thing between
a public-WAN router and a DNS amplification reflector. This line survives a future firewall edit that
the drop rule wouldn't.

### 22.4 NTP shipped in the same change, because certificates need a clock

Both fetch URLs run `check-certificate=yes`. A CHR booting with a skewed clock fails cert validation
on every fetch, which lands right back in guard 1. Safe, permanent and silent except for one log line
that reads exactly like an endpoint outage.

Servers are given **as addresses, not names**, so time sync doesn't depend on the resolver. Same
independence argument one level down. `use-peer-dns=no use-peer-ntp=no` on the ER DHCP clients
(§20.1) keeps both static lists authoritative. Without it a CGNAT'd 5G lease would slip the carrier's
resolvers and time servers in underneath us.

`/system/clock` sets `time-zone-autodetect=no time-zone-name=UTC` in the same block. Autodetect is the
RouterOS default and infers the zone from the router's public IP via MikroTik's cloud. An external
dependency nobody asked for, and it makes log timestamps depend on which provider a BR happens to sit
behind. Correlating a 3am event across four routers is hard enough without three of them disagreeing
about when 3am was.

### 22.5 Ordering and validation

The block is **first in `_mgmt.j2`**, which is included at `br.rsc.j2:9` and `er.rsc.j2:12`. So it
lands right after `/system/identity`, ahead of anything that touches a name or a certificate. The
§20.2 lesson again: `/import` is strictly ordered and you can't see that ordering in a diff.

`validate()` rejects an empty or missing `dns_servers` / `ntp_servers` and anything in `dns_servers`
that isn't a bare IP. That last check earns its keep. RouterOS won't take a prefix in `servers=`, so
`1.1.1.1/32` fails the import **partway through**, on a router that's already run
`reset-configuration`. Failing the build is free. Failing the import is a console trip.

## 23. The routing mark chose the WAN; the source address stayed on the other one

*A packet with an identity crisis, and the router that enabled it.*

`wan2` tunnels stopped completing their handshake. The symptoms couldn't have been more misleading:

| Where | What |
|---|---|
| ER, `wg-br2-wan2` | **zero bytes RX**, many bytes TX |
| BR, `wg-er1-wan2` | bytes RX **and** TX |
| ER log | `Handshake for peer did not complete after 5 seconds, retrying` |

Every line of that reads "Verizon is filtering inbound". It can't be. **`RX > 0` on the BR proves
the outbound leg works.** The initiation crossed ether2, the 5G CPE and the carrier CGNAT, so by
definition a mapping now exists. The BR's handshake response is the *reply leg of that mapping*, not
unsolicited inbound. `wan1` relies on the same traversal (§7, [docs/wireguard.md](docs/wireguard.md)).
If the carrier were the problem the outbound counter would be the one at zero.

Conntrack on er1 named it in one line:

```
1  C  protocol=udp src-address=192.0.2.186 src-port=51102
        dst-address=198.51.100.200 dst-port=51921
        repl-packets=0 repl-bytes=0
```

`192.0.2.186` is **wan1**. The packet was leaving ether2 wearing the Comcast address. No `SEEN-REPLY`,
`repl-packets=0`. And the wan1 tunnel one row up was `SAC` with traffic both ways. That's the tell:
same config path, one WAN working and one not.

### 23.1 Why a routing mark is only half of a policy route

RouterOS's output path is, in order:

```
Local Process -> Routing Decision -> Mangle Output -> Routing Adjustment -> ... -> srcnat
```

**The source address is assigned at the first Routing Decision, out of `main`.** `Mangle Output` is
where our mark lands, and it's only honoured at `Routing Adjustment`. That re-picks the *route* and
does **not** re-pick the source. So `via-wan2` correctly moved egress to ether2 and kept the source
address `main` had already chosen.

And what `main` chose wasn't random. The only main-table route to a BR public is the wan1 `/32`:

```
add dst-address=198.51.100.200/32 gateway=192.0.2.190 distance=1  comment="br2 via wan1"
```

No wan2 counterpart, because those `/32`s are gated on `w.gateway is defined` and a DHCP WAN
contributes no gateway. §20.3 called that harmless, correctly, for *reachability*. It isn't harmless
for **source selection**. That's the connection §20.3 missed.

`wan1` was never affected. There `main`'s preference and the mark agree, so the source matches the
egress by accident of both pointing at the same interface.

### 23.2 The CPE is what converts a wrong source into a silent black hole

This didn't fail cleanly at the ER, which is why the counters lied:

1. ER emits on ether2 with `src=192.0.2.186`.
2. The 5G CPE masquerades it anyway. Consumer NAT translates what it forwards. It doesn't audit the
   source against its own LAN.
3. br2 receives a valid handshake and answers it. **Both BR counters move.**
4. The answer comes back through the CGNAT and the CPE un-NATs it to `dst=192.0.2.186`...
5. ...and then *routes* it out its own uplink, because `192.0.2.186` isn't on its LAN.

The response never touches ether2. The ER's `drop in-interface=ether2` counter stays at background
scan noise (422 packets against 1708 handshake retries), so even the firewall looks innocent.

### 23.3 Why this appeared now

Because §20 fixed the thing hiding it. The old `script=` never installed a default into `via-wan2` at
all, so these packets weren't egressing ether2 in the first place. `default-route-tables=via-wan2`
made them do so **for the first time**, and that exposed a source-address mismatch latent since the
mangle rules were written. The `wan2` tunnels had been up on the strength of not actually using
`wan2`.

Plainly: **a fix that makes a dormant path live publishes every bug on that path.** §20 was correct
and still is.

### 23.4 srcnat, because it is the first hook that can see the real egress

```
/ip/firewall/nat
add chain=srcnat action=masquerade out-interface=ether2 protocol=udp \
    dst-port=51920-51929 comment="WG outer -> wan2: src must match egress"
```

`srcnat` runs *after* `Routing Adjustment` so `out-interface=` matches the interface the mark actually
picked. `masquerade` instead of `src-nat to-address=` because a DHCP WAN has no address to hard-code.
The ER's own conntrack un-NATs the reply before the filter sees it, so the input chain keeps accepting
it as `established` and **no new hole opens for it**.

`pref-src=` on the `via-wan2` route was considered and rejected. The source is chosen from `main`
before the adjustment, so a preference on the adjusted route is consulted too late.

**Confirmed on er1/er2 2026-08-10** via reset-and-restore (§18), not a live rule add. §23.8 says why
that distinction mattered. Both `wan2` peers took RX and completed a handshake.

**Rendered for every WAN, not just the one that needs it.** On whichever WAN `main` already prefers
it's a no-op. And *which* WAN that is falls out of which ones happen to be static. Not a fact to bake
a rule set around. Promoting wan2 to primary is meant to be a cost change (§7), not a re-think of
which interfaces need source correction.

### 23.5 Why NAT is safe on a router whose transit is deliberately stateless

The ER `notrack`s everything not addressed to itself, and an untracked packet **can't be NATted at
all**. So the customer fast path is out of this rule's reach by construction, before its match is even
looked at. The match then narrows it again to udp + one WAN's outer port range + one interface.

The tunnels' own outer flows *are* tracked, and this depends on it. That raw rule is
`chain=prerouting` and router-originated packets never traverse prerouting. The same fact makes the
`established` accept in the input chain work at all, so this adds no new dependency. It leans on the
one already holding the return path up.

### 23.6 The port ranges now have one home

`51820-51829` / `51920-51929` were literals in the mangle rules. A second consumer would've made three
copies of arithmetic that already lives in `derive()` as `br_port`. So the base is now `wan_port_base`
there and each ER WAN carries a ready-made `wg_ports` range. `validate()` rejects a WAN whose id has
no derived range instead of rendering an empty `dst-port=`. The BR configs are byte-identical across
the refactor, which is the check you want: `br_port` is the same number, sourced differently.

### 23.7 What to look at when a tunnel is one-way

In this order, because the first one is decisive and free:

```
/ip/firewall/connection print detail where protocol=udp dst-address~"<BR public>"
```

`src-address` is the address the router actually used. Wrong WAN's? Stop, it's this bug.
`repl-packets=0` with no `SEEN-REPLY` means the response never matched the flow.

```
/ip/firewall/filter print stats where chain=input
```

If the per-WAN `drop` counter tracks the handshake retry rate, the response *is* arriving and
conntrack isn't matching it. Different failure. If it sits at scan-noise levels the response isn't
arriving, and the question is where the source address sent it.

**Don't start at the carrier.** The direction of the working counter tells you which leg is broken.
On this fleet a broken *inbound* leg with a healthy outbound one has never once been the carrier.

### 23.8 A srcnat rule added by hand does not fix a flow that already exists

The rule went onto er1 live first and nothing changed. Still zero RX. The rule wasn't wrong. **NAT is
evaluated only on the first packet of a connection.** The conntrack entry for
`192.0.2.186:51102 -> 198.51.100.200:51921` predated the rule so it carried no NAT binding, and every
later packet followed the path already recorded in it. The rule never gets another look.

That flow never ages out either. WireGuard retries every 5s, refreshing a 27s timeout forever. So the
stale entry pins the tunnel to the broken path as long as the router stays up. A `nat` rule counter of
**0** is the tell. A healthy one counts once per *connection*, not per packet, so low numbers there
are normal and prove nothing.

Clearing it is per-flow and should stay that way:

```
/ip/firewall/connection remove [find where protocol=udp dst-port=51921]     # er1; er2 is 51922
```

**Don't flush the wan1 entries to be thorough.** Those tunnels work and masquerade is a no-op on
them. With BFD armed at 300ms x 4 (§19) there's a window where an inbound packet with no conntrack
entry gets dropped as `new` and flaps an adjacency that had nothing wrong with it.

None of this applies to how this network is actually configured. `reset-configuration` +
`run-after-reset` (§18) hands the `.rsc` a box with an empty conntrack table, so the rule is in place
before the first handshake leaves and there's nothing to retrofit. The hand-apply was a diagnostic
shortcut, and the shortcut produced the confusing second data point.

**One trap in picking the reset path, worth more than the shortcut it avoids:** `out/` was stale.
`generate.py` had been failing `validate()` on an unrelated half-finished customer entry, and
`validate()` runs before rendering. So the `.rsc` files on disk were the pre-fix render, and
`deploy.yml`'s preflight only asserts the `.rsc` *exists*, not that it's current. A fleet-wide reset
would've faithfully restored the exact bug it was meant to clear. **Rebuild and confirm the fix is in
the rendered file before any deploy that resets anything.** `grep -c srcnat out/er1.hdc.rsc` is the
whole check.

---
## 24. Remote sites — one MikroTik per site, meshed to every BR

The `sites:` block sat empty from the start with a three-line sketch in it: `delegation`,
`primary_br`, `backup_br`. Two of those are now gone and the third is derived.

### 24.1 No primary/backup. That was the whole point of the WireGuard mesh.

Pinning a site to a primary BR with a backup is what you reach for when tunnels are expensive to
build and keep. Here they're neither. A tunnel is a `/31`, a keypair and a listen port, and the ERs
have proved the alternative for a year: four tunnels each, no primary, WAN preference expressed
*only* as OSPF cost. A site that forms the same kind of connectivity gets the same treatment.

So a site router dials **every** BR, joins the **full iBGP mesh** and lets OSPF pick. Concretely,
"br1 is down" and "br1's eBGP is down" stop being different events for a site. With primary/backup
the first is a failover and the second is a black hole (the site keeps sending to a BR whose upstream
is gone). In the mesh the first is a reconvergence and the second is `default-guard` setting
`default-originate=never` on one of several sessions the site already has. No failover logic
anywhere, because there's nothing to fail over.

The cost is address space and it's real. See §24.3.

### 24.2 The site device is the site's WAN router, and that deletes a layer

At `hdc` the ERs hand a `/29` transit segment to firewalls that peer eBGP and claim VIPs out of the
`/25`. That machinery exists because home space is *shared*. Several boxes carve one block, so the ER
needs a per-customer security boundary and a liveness signal that's a real advertisement, not a ping.

A site owns its whole delegation so none of that applies. The `/29` is **attached** to the site
router. It holds the first usable address as the inside default gateway and the other five are routed
directly. No NAT, no eBGP session, no VIP filter chain. Origination is gated on the *connected
route*: LAN down → no connected `/29` → `output.network` stops advertising. A stronger liveness
signal than the ERs' anchor-plus-guard, and no script needed.

v6 doesn't get that for free, and the asymmetry is deliberate. A site holds a `/48` of which the LAN
is one `/64`, so no connected route covers what's originated. The `/48` rides a distance-254
blackhole anchor exactly like the ERs' `home-anchor`. So v6 origination is gated on the *router*
being alive, not the LAN being up. Same drop either way (the traffic dies at the site instead of at
the BR). It only affects `anchor-guard`'s "is anyone delivering" count, which is still unarmed.

**Not new, but it shows up here:** the forward chain is empty on a site router, like on every router
in this AS, and a site's `/29` and `/64` are publicly routable. At `hdc` pfSense stands between a
client and the internet. At a remote site nothing does unless the inside device is a firewall. Every
generated site config says so at the top instead of leaving it to be discovered.

### 24.3 Four sites, and the constraint is v4 P2P space — not delegations

`blocks.site_p2p` is a `/28`. **Eight `/31`s, and that's every site tunnel this AS can address in
v4.** One WAN per site × two BRs = two per site, so it holds four sites. Exactly the four `/29`s in
`site_deleg`. The two blocks run out together. Tidy and entirely accidental.

`SITE_BR_SLOTS` reserves a *fixed* run per site instead of packing densely, for the same reason the
BR↔ER offsets are fixed: adding site2 must never renumber site1's live links. The price is that **a
third border router overflows the block**, and `generate.py` refuses to render instead of quietly
renumbering. The error names all three ways out and none is free. Fewer sites. Re-carve the `/24`
(nothing's spare, every block is allocated). Or move site tunnels to v6-only addressing, where
`2001:DB8:0:20::/60` has no such limit.

Remember that last one. This is the one place in the build where **v6 is the unconstrained family
and v4 is what's in the way.**

### 24.4 `default-guard` was already broken for anything that wasn't called `er*`

The BRs' `default-guard` found its downstream sessions with `name~"^ibgp-er"`. A site's session is
named for its site code (`ibgp-sfo`), so the guard would've skipped it silently. And the failure is
precisely the one the guard exists to prevent, at the router least able to notice. A site handed a
default by a BR whose eBGP is dead, sending traffic that dies at the upstream's BCP38 filter.

It's now a rendered literal list of connection names generated from `ibgp_peers`. **This is the only
functional change to the existing BR configs.** With `sites: []` the list is exactly what the regex
used to match, so behaviour is unchanged. But the bytes differ and br1/br2 will show as CHANGED on the
next `deploy.yml` run.

The underlying mistake was a regex over *names* to find things by *role*. Don't repeat it. The
generator knows every peer's role, so the filtering belongs there, not in a pattern the router
re-evaluates at runtime.

### 24.5 The site LAN is inside the management source list

`accept src-address-list=mgmt` sits **above** the terminal drop in every input chain. Anything on that
list is a management source whatever interface it arrives on, and the tunnels carry it to every other
router in the AS.

At `hdc` that's academic. The `/24` holds infrastructure and VIPs behind pfSense. A remote site puts
**ordinary client devices** in the same `/24`, so any `mgmt_prefixes` entry covering the site's `/29`
makes every device someone plugs in there a management source for the whole fleet.
`mgmt_prefixes_url` currently returns `203.0.113.0/24`, which does exactly that.

`generate.py` warns at build time when a site's delegation is inside the management list, and the
generated config repeats it in the input chain where someone reading the drop rule will see it.
Neither fixes it. Narrowing the endpoint's answer is the fix, and that's a policy call, not a build
one.

### 24.6 Naming: `sr`, not a second kind of `er`

A site router is `sr1.<site>`. `sr` for site router, loopbacks `.245`–`.248`, v6 `::51`–`::52` (hex
has no `s` and `5` is the only nibble that reads like one). Calling them `er1.<site>` would've been
free in one sense, since the BRs' `role == 'er'` branches and the ERs' `ibgp-out-er` chain would've
covered them automatically. And wrong in every other. A site has no sibling, no interconnect, no
customer firewalls and one WAN. Two really different configs sharing a role code is how a filter
chain ends up applying to something it was never written for.

What the ERs *do* share with sites is output policy, expressed as a separate derived field
(`ibgp_out_class`) instead of overloading the role. A site is `sr`, and on output an ER treats it
exactly like a BR. One chain, one meaning, no second copy of `ibgp-out-br` to keep in step.

## 25. The Comcast static block went away, and `wan1` moved onto the gateway's LAN

`192.0.2.176/28` was the Comcast static add-on. Dropped. The circuit itself stays. That block was
`er1`/`er2` `wan1` (`.186` and `.187`, both pointed at `.190`) so both ERs needed new addressing on
`ether1`.

What's worth recording is how *little* had to change, and why that wasn't luck.
(Okay, a little luck. But mostly not.)

### 25.1 The management dependency had already been paid off

The painful version of this change is the one where `mgmt_prefixes` was still `192.0.2.176/28`.
Cancelling the circuit would've taken the underlay and the management source in one move, and the
warning that used to sit above that key in `topology.yml` said exactly that. By the time the statics
went, the floor had already moved to `203.0.113.0/24`.

So the SSH/Winbox ACLs, the `mgmt` address-list and the `mgmt-refresh` floor were untouched. That's
the whole reason it was a two-line topology edit and not a console-cable weekend. The warning did its
job. It lasted long enough to be acted on before the deadline.

### 25.2 Static on the ISP gateway's LAN, not DHCP

DHCP was the obvious option. `er.rsc.j2` has had the fork from the start (`address` present ⇒ static,
absent ⇒ dhcp-client) and `wan2` has run the DHCP side since §20. Not taken.

What decided it: **the substitution is 1:1.** Both ERs were already two hosts on one L2 segment
behind the gateway, sharing one next hop. The gateway's private LAN keeps that exact shape. Same
segment, same single gateway, same two hosts. Only the numbering and the NAT change. A dhcp-client
would've been a *different* shape for no gain, and it would've dropped the BR-public `/32` pins in
`er.rsc.j2` (they're gated on `wans[0].gateway` being defined).

The mapping, straight across:

| | was | is |
|---|---|---|
| er1 `wan1` | `192.0.2.186` | `172.20.101.11` |
| er2 `wan1` | `192.0.2.187` | `172.20.101.12` |
| gateway | `192.0.2.190` | `172.20.101.1` |

`172.20.101.0/24` is fresh space. There's no other RFC1918 anywhere in the topology, the templates or
`generate.py`. Everything else in AS64500 is publicly addressed. And it stays local. There's no
`redistribute` in `er.rsc.j2` at all and the OSPF interface-templates are an explicit allow-list
(`lo0`, transit, xc, `tun-wan1`, `tun-wan2`) that never names `ether1`. The connected WAN route can't
reach the IGP or BGP.

Those pins aren't what keeps things working. The mangle mark → `via-wan1` → masquerade triad is what
actually pins outer flows and fixes source selection, and it renders for every WAN regardless. But
that's a reason not to *panic* about losing them. Not a reason to lose them.

**The cost, and it's real:** the gateway's LAN subnet is now a literal in `topology.yml`. A gateway
RMA or a firmware push that changes the LAN numbering takes **both ERs down at once, silently, with
no self-healing.** A correlated failure across the pair. The exact class of thing the rest of this
design spends a lot to avoid. Accepted with eyes open, because §25.4 makes it recoverable without a
console cable. If that ever stops holding, revisit this decision before anything else.

### 25.3 Two things that were already right, and would have been easy to break

- **`persistent-keepalive=25s`** on every ER peer. Used to be belt-and-braces for the CGNAT'd `wan2`.
  Now `wan1` is behind the gateway's NAT too, so it's the only thing holding that binding open between
  packets on *both* WANs.
- **`action=masquerade`, not `src-nat to-address=`.** Chosen in §23 "because a DHCP WAN has no
  address to hard-code". A reason unrelated to this change that covered it anyway. A hard-coded source
  address would've needed editing here. Masquerade didn't.

The one to watch on the next `/interface/wireguard/peers print stats` is TX moving with RX flat. The
§23 signature (source address disagreeing with the egress WAN) and the only failure this change could
plausibly have brought back.

Both ERs now sit behind one NAT. Fine, not worth worrying about. `br_port` encodes the ER index
(`51821` vs `51822`) so the two ERs' flows differ in the 5-tuple before the gateway ever sees them.
Nothing for its PAT to disambiguate.

### 25.4 Ansible now reaches the ERs on their transit addresses

`ansible_host` for `er1`/`er2` was the `wan1` address. Now it's `203.0.113.233`/`.234`,
`home.transit_er1`/`transit_er2`.

That's *better* than what it replaced, not just equivalent. The ER input chain accepts
`in-interface=<transit>` **unconditionally**, ahead of both the `src-address-list=mgmt` accept and the
WAN drops. So that path holds with every tunnel down, BGP dead and the `mgmt` list wrong. The
loopbacks were the other candidate and lose for one reason: they need OSPF and BGP up, so they're dark
exactly when you need them.

Sequencing followed: **repoint the inventory and prove it while the statics still work.** Everything
after that step is recoverable. Nothing before it is.

### 25.5 The check that should have existed already

ER WANs were validated for one thing only: that a derived outer-port range existed. No `address` XOR
`gateway` check, though `sites:` has had one since §24. No gateway-inside-the-subnet check, though
the BRs have had one since §17.

That gap is invisible in the worst way. An ER with an address and no gateway renders a clean `.rsc`
and imports without complaint. You get a box with an address on `ether1`, no default in `via-wan1`
and (because the pins are gated on the same field) no `/32` pins either. A gateway with a typo'd octet
does the same. Both are now build-time failures with a message naming the consequence, because "the
config generated fine" is the least useful thing a router can tell you while it's unreachable.

The general note: this is the second time a check that existed for one role turned out missing for
another (§17 for BRs, §24 for sites, ERs neither). The roles are similar enough that a *missing* check
reads as "not applicable here" when it really means "nobody wrote it yet."

### 25.6 Both home WANs are now NAT'd, and the docs said otherwise

`docs/wireguard.md` argued the ERs must be the initiators *because `wan2` is CGNAT'd*, and closed
with: if `wan2` ever gets a static public IP, the constraint relaxes.

That sentence wasn't just stale, it was backwards. The relaxation it anticipated arrived as its
opposite. `wan1` lost its public address so the constraint is now **unconditional**. There's no ER
WAN a BR can dial into, and the implicit escape hatch ("well, `wan1` has a real address") is gone.
Rewritten to say so, along with `docs/addressing.md`, which described `wan1` as fibre with a public
static.

---
## 26. Traffic engineering — two directions, two mechanisms, one flag each

The network was multihomed with no way to prefer one upstream over the other. Adding that took four
decisions, plus one bug found while looking.

### 26.1 The bug: "ECMP multihoming" was a router-id tie-break

An ER hears `0.0.0.0/0` from br1 and from br2. The two are identical in every attribute best-path
looks at (same local-pref, same empty AS_PATH, same origin, same MED) and identical in the tie-break
after that. Both BR loopbacks sit behind the *same* `tun-wan1` interface so OSPF returns the same
metric for each. There's one WireGuard interface per WAN with a peer per BR, not one per BR, and
that's deliberate ([§7.1](#7-edge-router--er1hdc)). The cost is per-interface.

With no `multipath` on `/routing/bgp/instance`, RouterOS installs **one** of them and breaks the tie
on router-id. So the egress BR was already pinned. Arbitrarily, by an accident of loopback numbering,
in a network everyone described as ECMP.

The same gap made a comment in `generate.py` untrue. The shared-grant check says "all owners at
equal/absent `local_pref` → the ERs install ECMP," and without multipath they didn't. So
`bgp_multipath` is now a top-level knob and "no preference" means load sharing.

Watch the BRs on first deploy. Their equal-cost pair is the home `/25` from er1 *and* er2, so inbound
traffic to home now spreads across both ERs instead of parking on whichever won a tie-break. What the
design always described.

### 26.1.1 It is a COUNT, and shipping it as a switch cost br1 its BGP config

The knob went out as `bgp_multipath: true` → `multipath=yes`, defaulted on. br1 came back from its
deploy with **no BGP instance, no connections, no filter chains, no sessions**. Otherwise healthy and
reachable, which is what made it confusing instead of obvious.

`/routing/bgp/instance multipath` is typed **`num`**: *"install the specified number of ECMP routes."*
`yes` is a type error. The import stops at that line, and since it's the first line of the
`/routing/bgp` section **every BGP object below it never gets created**. Instance, templates,
connections, every filter chain. `reset-configuration ... run-after-reset=` means the failure lands
*after* the box was wiped, so there's no previous config to fall back to. The router boots, answers
SSH, passes the playbook's identity assertion and routes nothing.

Three things went wrong and only one is RouterOS's fault:

1. **The repo already had the right answer and got overruled.** [§6.4](#64-seven-decisions-that-must-not-be-simplified-away)
   ends with "**`multipath=<n>` on the instance** if you want BGP ECMP." `<n>`. That note came from
   the documentation and was then contradicted by a plausible-looking `multipath=yes`. When this file
   and a guess disagree about RouterOS syntax, this file wins. That's what it's for.
2. **It shipped defaulted ON while explicitly recorded as unverified.** The risk was written down
   before the change, right next to "verify it on a live router first," and the default went to
   `true` anyway. A knob nobody has watched a router accept defaults to OFF. The convention
   [§19](#19-bfd--sub-second-liveness-under-ospf) already set for BFD, and it exists for exactly this.
3. **There's no dry run.** RouterOS `/import` has no validate mode and this deploy path destroys the
   running config before the script runs, so the repo can't tell you whether the box accepts a line.
   One reversible command on a live box can, and it now sits in `topology.yml` next to the knob:

   ```
   /routing/bgp/instance set [find name=core] multipath=2
   /routing/bgp/instance print detail where name=core
   /routing/bgp/instance set [find name=core] !multipath
   ```

So `bgp_multipath` is now `false` or an int in `2..16`, defaulted **false**. `validate()` rejects
`true` *by name* with a message saying what `yes` does to the import, instead of helpfully translating
it. Helpfully translating it is what caused this.

The value still goes to the router verbatim instead of being hardcoded in the templates, and that paid
off. The property has moved across RouterOS versions, so the correction was one line in
`topology.yml` and not a template change across three.

**The general rule.** A RouterOS property not already somewhere in these templates is unproven until a
live box accepts it. Add it OFF, prove it on one router by hand, then turn it on. On this deploy path
an unproven property doesn't fail the deploy. It leaves a running router with a silently truncated
config.

### 26.2 Per-BR flags, not a global `primary:`

The obvious shape was one `traffic_engineering: { mode: ..., primary: br1 }` block. One statement of
intent, trivially validated, every non-primary BR automatically the backup.

Rejected for what it can't express. A global `primary` forces ingress and egress onto the same BR, and
there's no reason they should be. An upstream can have better eyeball reach than transit pricing or
the reverse, and pulling inbound to br1 while pushing outbound through br2 is a fair thing to want.
Per-BR `te: { prepend, local_pref }` gives that for free and generalises to a third BR with its own
tier instead of a binary primary/everyone-else.

The cost: consistency becomes the operator's problem. That's 26.3.

### 26.3 All-or-nothing validation, including the losing value

`te: { local_pref: 200 }` on br1 with no `te` on br2 *works*. It works by pairing 200 against
RouterOS's default of 100. A number that appears nowhere in `topology.yml` and that nobody chose.

Same trap the shared-grant check has refused since [§14](#14-the-customer-grant-model--enumerated-vips-vs-delegations).
A partial set silently pairs your value against a default and picks a winner you didn't intend. So
whichever key you set, `validate()` requires it on **every** BR, including the explicit `prepend: 0`
or `local_pref: 100` on the preferred one. One extra line and the comparison is written down where
you change it instead of inherited.

It also bounds the [§26.2](#262-per-br-flags-not-a-global-primary) cost. A third BR added later fails
the build instead of quietly landing on defaults while the other two get steered.

### 26.4 Egress local-pref is set by the RECEIVER, on input

Textbook placement is the sender. br1 stamps local-pref 200 on its own `ibgp-out`, one rule in one
per-BR chain, no change to `er.rsc.j2` at all. The smaller diff by a mile.

The problem is what it'd be stamping. The default route is *generated* by
`output.default-originate=if-installed`, and whether RouterOS runs a generated route through the
output filter chain isn't documented well enough to bet a live network on. If it doesn't, the feature
silently does nothing. Same failure shape as `network-blackhole=yes` quietly disarming `anchor-guard`
([§6.4](#64-seven-decisions-that-must-not-be-simplified-away)), where everything looks configured and
nothing happens.

An inbound UPDATE definitely traverses `input.filter`. So the value is applied at the ER and the site,
on input, per peer. That meant moving `input.filter` off the `ibgp` template onto each connection.
Exactly the move `output.filter-chain` already made in `er.rsc.j2`, for the same reason: a template
carries one value and these peers need different ones.

Chains are named for the **value**, not the peer (`ibgp-in-lp200`), so two BRs at the same preference
share one chain. Same reasoning as `ibgp_out_class`. A per-peer chain would just be a second copy of
identical rules to keep in step.

The BRs keep their plain `ibgp-in` on purpose. A BR must never prefer a sibling's default. It'd egress
through the sibling's transit and get its own-sourced packets dropped at that provider's BCP38 filter,
which is the whole reason `provider_default_distance` is 30.

### 26.5 The prepend is scoped to the aggregate and sits *above* the `2:N` ladder

Two placement choices in `ebgp-out-upstream`. Get either wrong and it breaks.

**Scoped, not at the head of the chain.** A bare `set bgp-path-prepend 5` before the jump would also
prepend RTBH `/32`s. A blackhole request wants the *shortest* path to the upstream (`65535:666` stops
the traffic, not distance) so the rule matches the aggregate and nothing else.

**Above the ladder, so the community wins.** `set bgp-path-prepend` assigns, it doesn't accumulate,
so the last rule to run is the one that ships. Emitting the static value first lets a runtime
`64500:2:N` tag out-vote `topology.yml` on one prefix without a regenerate-and-redeploy.

For the record, the `2:N` tags never could do this job. The aggregate is originated locally from the
anchor and carries no communities, so no `2:N` rule has ever matched it. They're a per-prefix operator
hook for something you're actually carrying in BGP. `docs/communities-rtbh.md` now says so instead of
implying they're the prepend mechanism.

### 26.6 What is deliberately not validated, and one axiom that survives

**Split preference is allowed.** In via br1, out via br2 draws no warning. Asymmetric routing breaks
when a stateful device sees one direction of a flow and none sits on the split path. Transit on the
BRs is `notrack`'d ([§6.4](#64-seven-decisions-that-must-not-be-simplified-away)) and the customer
firewall stays on-path both ways whichever BR carries which half. Both upstreams accept the `/24` as a
source because we announce it to them.

**"WAN preference is expressed only as OSPF cost, never in BGP" still holds.** That rule is about
`wan1` vs `wan2` (which WAN reaches a given router) and it's still `ospf_cost` and nothing else. This
feature is about which *border router* the AS prefers. Orthogonal axes. Prefer br1 and lose wan1, and
OSPF reroutes to br1 over wan2 with the BR preference untouched. Lose br1 and BGP moves to br2 with
the WAN preference untouched. An ER's `set bgp-local-pref` chooses a border router. Wanting `wan1` vs
`wan2` in a BGP attribute is the rule telling you to change a cost instead.

Full mechanism in [`docs/traffic-engineering.md`](docs/traffic-engineering.md).

---

## 27. The customer's half of the session is generated too

`firewalls:` has always described a session with two ends and rendered one of them. The ER end is
`cust-in-<fw>` plus `cust-out`, derived from the grant. The far end was left to whoever ran the box, in
whatever syntax that box speaks.

**Chosen:** a `type:` on the firewall entry, and the same claims that build `cust-in-<fw>` also build
the firewall's own config. `unifi` today (`out/<name>.unifi.conf`, FRR format. UniFi's BGP *is* FRR,
uploaded at Settings → Routing → BGP). `pfsense` is a recognised value with no renderer yet. Absent is
the default and stays the default.

### 27.1 Why generate it at all — the failure is a *working* session

The obvious objection: this is the customer's business, and the ER filter is the security boundary
either way. Both true. Neither is the point.

Hand-writing the far end states the grant **twice**, in two syntaxes, kept up by two people. The
failure that produces isn't a session that won't come up. That one's loud and gets fixed in ten
minutes. It's a session that comes up and quietly carries less than it should:

- a VIP granted in `topology.yml` and never advertised by the firewall, so the `/25` is missing an
  address everyone believes is live;
- a LAN the firewall advertises into a filter that rejects it, so the customer sees the route in its
  own table and nowhere else;
- worst, the **last** VIP in the first case. A live VIP advertisement is what gates the home anchor
  ([§13](#13-vrrp-retired--bgp-is-the-reachability-and-health-signal)), so a grant that's never
  advertised is a `/25` that's never originated.

Every one of those reads as "BGP is up" from both ends. Deriving both halves from one grant removes
the class, not just the individual bugs.

### 27.2 The generated file mirrors the ER rather than trusting it

The outbound prefix-list **is** the `cust-in-<fw>` whitelist, line for line. An exact `allowed_vips`
entry is one prefix at one length. A `delegations` block is the block plus `le <max_len>`. Nothing is
offered that the ER isn't already set to accept, so the ER never rejects anything in normal operation
and a rejection means something's actually wrong.

The **inbound** list is the more interesting half: `permit 0.0.0.0/0` and nothing else, no `le`.
`cust-out` already rejects everything but the default, so this is redundant. On purpose. The two ends
are rebuilt together but *deployed* separately, and the window where one is newer than the other is
exactly when a leak would land. A customer filtering its provider isn't being rude. Same reasoning
that puts a terminal `reject` on `cust-in`.

### 27.3 The two shapes advertise by two different mechanisms

`allowed_vips` becomes `network` statements. `delegations` becomes `redistribute connected` filtered
through the outbound route-map.

They can't share one mechanism. Enumerating a delegation defeats the point of granting one. A block
exists so the customer can carve it up *without* a change at the ER, so a `network` line per LAN
would put the enumeration back, in the wrong file. Redistributing connected routes for an enumerated
VIP is worse the other way. It advertises whatever happens to be attached and calls it the grant.

The route-map on the redistribution does real work and it's the same one used on egress. A UniFi
gateway's connected routes include the transit segment and every private LAN behind it. The
prefix-list stops those entering BGP at all, instead of relying on the ER to reject them after
they've been sent.

### 27.4 `maximum-paths`, because FRR installs one path by default

Both ERs advertise the default with identical attributes. FRR picks one and installs one. So a
customer on a segment built for ECMP quietly sends every outbound packet to whichever ER won the
tie-break, and the design's claim that the firewall "ECMPs its egress across er1/er2"
([§13](#13-vrrp-retired--bgp-is-the-reachability-and-health-signal)) is fiction on that box.

It's derived from the ER count, **not** from `bgp_multipath`. That number is a RouterOS instance
property with its own type trap ([§26.1](#26-traffic-engineering--two-directions-two-mechanisms-one-flag-each)).
How many next-hops a *customer* installs is a different question, and the answer is "however many ERs
are advertising to it". An ER that loses its own upstream stops originating the default
(`default-originate=if-installed`) and leaves the set without anyone editing anything.

### 27.5 No RFC 9234 role, deliberately

The ERs carry `local.role=ebgp-customer`, an RFC 9234 role, and FRR can set one with
`neighbor <ip> local-role`. The generated file sets none.

RFC 9234 needs the two ends to be **complementary**, and a wrong pairing isn't a filtering subtlety.
It's a Role Mismatch notification and a session that never establishes. Sending no role capability is
the case the RFC handles by skipping the check, so it's the one answer that can't be wrong from this
side. Adding a role here means changing both ends in one rebuild. Otherwise it's a broken session.

### 27.6 An unknown `type` is refused; a known one with no renderer is not

`unfi` fails the build. `pfsense` renders everything else, writes no peer config and says so on
stderr.

That's the difference between a typo and a plan. A typo silently skipped leaves an ER configured and
waiting for a session whose other end was never built. Exactly the silent-shortfall class this section
exists to close. A dialect that just isn't written yet is a known gap, and failing the whole render
over it would take the *routers* down for a feature that has nothing to do with them.

---
## 28. SNMPv3 — the collection half of §11

§11 always listed what to watch and never said how the numbers leave the box. Everything that *acts*
on a failure already runs on the routers (`anchor-guard`, `home-anchor-guard`, `default-guard`,
OSPF+BFD), so monitoring isn't in the failure path here. That's why it took this long to add. It's
also why it could be added without touching anything the network depends on.

**Chosen:** one SNMPv3 user, `security=private` (authPriv: SHA1 auth, AES encryption), read-only,
restricted by an input-chain accept for `udp/161` from a named source list. Passphrases generated
into `keys.json`, and the agent block rendered **last** in every `.rsc`. Zabbix polls the loopbacks.
No v1, no v2c, no traps, no per-router credentials. `topology.yml` carries the switch, the poller's
address and the algorithm names. Nothing else.

Mechanism and the operator's side: [docs/snmp.md](docs/snmp.md).

### 28.1 v3 or nothing — and `public` is neutralised either way

SNMP v1/v2c authenticates with a community string. A password, in cleartext, over UDP, on a router
whose `ether1` faces the DFZ. RouterOS ships with one already configured, named `public`,
`security=none`.

That default is the real decision here, not the choice of v3. **The templates set `read-access=no` on
`public` on every router whether or not SNMP is ever enabled.** A CHR answering `public` isn't an
information leak. It's a UDP amplifier with someone else's address in the return field, and the first
thing anyone learns from the MIB is the topology of everything it's connected to.

`read-access=no` instead of `remove`. `/snmp trap-community` still points at `public` by default, and
removing a referenced object is the kind of line whose behaviour varies by RouterOS version. Denying
read is total and can't fail.

### 28.2 The poller gets its own address list, not `mgmt`

Every input chain accepts `mgmt` **wholesale**. Every protocol, every port, SSH and Winbox included.
Putting the poller there would've been one line.

A monitoring server is the one box that talks to every router *and* a web app with users, plugins, a
database and a browser-facing login. Putting it on `mgmt` trades the fleet's whole management surface
for a saved line of config. It gets `list=snmp` and one rule: `protocol=udp dst-port=161`.

The two lists also fail differently, which is why they stay apart. Widen `mgmt` by accident and you
hand out administrative reach. Widen `snmp` and you hand out read-only counters.

### 28.3 The passphrases are not in `topology.yml`

`topology.yml` opens by promising it holds no secrets. Two SNMPv3 passphrases in it would repeat the
WireGuard mistake this repo already refuses to make. So they live in `keys.json` (mode 0600,
gitignored) under `snmp:<user>`, generated once and reused forever, on the same idempotency contract
as every tunnel key.

32 URL-safe characters. The alphabet isn't cosmetic. `A-Za-z0-9_-` can't contain the `"` or `\` that
would break out of the quoting in the rendered `.rsc`. And breaking out of a quote in a file applied
by `/import` **after `reset-configuration`** isn't a syntax error you catch in review. It's a router
you drive to.

The one place they get typed again is Zabbix, so the build writes `out/snmp_zabbix.env` in Zabbix's
own macro names. With `private` translated to `authPriv` and `AES` to `AES128`, the two places
RouterOS and Zabbix name the same thing differently and fail as a silent timeout.

### 28.4 Rendered LAST in every file, and it is the only block placed by that argument

`/import` is strictly ordered (§20.2) and `deploy.yml` runs it straight after `reset-configuration`
(§18). A rejected line abandons every line below it on a box that's already been wiped. Same trap
`multipath=yes` fell into (§26.1), and that one cost a rebuild.

`authentication-protocol` and `encryption-protocol` are the two properties here whose accepted values
move between RouterOS versions. MikroTik documents `MD5|SHA1` and `DES|AES`, newer builds take
`SHA256`/`SHA512`, and this file renders whatever `topology.yml` says. So the whole block goes last in
every `.rsc`.

**That asymmetry is the whole argument. Get it wrong here and you lose monitoring, which you find out
about from outside within one poll interval. Get it wrong anywhere above and you lose the firewall,
which you wouldn't.**

`generate.py` refuses `MD5` and `DES` **by name**, with their own error messages, instead of letting
them fall out of a "not in the allowed set" check. They're not typos. They're a choice, and the answer
isn't "pick another one from the list".

### 28.5 One user for the fleet, not one per router

Per-router passphrases are strictly stronger and got rejected anyway. They mean two host macros per
host, kept up by hand, for a credential that's read-only, source-restricted and worthless to anyone
who can't already send packets from the poller's address. Little security bought, and the cost is
paid on every router added forever.

Rotation is the honest cost. `--rotate-keys` regenerates *everything* including WireGuard, so the
SNMP-only path is deleting the `snmp:<user>` entry from `keys.json` and rebuilding. Update Zabbix in
the same window. Until you do, every host goes unreachable at once and no log on either side says why.

### 28.6 No traps; one engine-id per router

`trap-target` stays at its `0.0.0.0` default. A v3 trap needs the **receiver** taught each router's
engine-id. Per-router state to maintain, in exchange for duplicating data Zabbix already polls. The
events actually worth waking someone for are `:log warning` lines from the guard scripts, and shipping
the log is one syslog target with no engine-ids in it.

This section first said `engine-id` would be left alone, on the grounds that RouterOS derives a unique
one per device. **It doesn't.** With `engine-id-suffix` empty, every router on 7.24.5 reported
`80003a8c04`, MikroTik's prefix and nothing else. SNMPv3 keys engineBoots and engineTime by engine-id,
so Zabbix kept the clock of the first router it reached (er1) and dropped every other router's
replies as outside the time window. It showed up as `Timeout while connecting` on three of four hosts,
with ICMP clean and `snmpwalk` from the poller working. Enough to send the first look at the firewall.

`_snmp.j2` now renders `engine-id-suffix=<fqdn>`. Unique by construction, stable across a CHR
rebuild, readable in `/snmp print`. `generate.py` refuses a suffix over 27 octets (32 minus the
5-octet prefix) and refuses two routers sharing one. Changing a live router's engine-id needs a
`zabbix-server` restart to flush its in-process engine cache.

**A package install resets engineBoots too.** Going 7.24.5 → 7.25.1, every router came back reporting
`engineBoots=1` where Zabbix had cached 3 and 4 (plain reboots before that had incremented it
normally). RFC 3414 only lets a manager accept a correction that moves boots forward, so Zabbix
discarded every reply as `notInTimeWindow`. The same "Timeout while connecting" on every host,
firewall counters clean, routers answering on the wire. A capture is what showed it. That's RouterOS
breaking the RFC, and the engine-id can't work around it (rotating it per upgrade dodges the cache
once, then a redeploy restores an engine-id Zabbix still holds a high counter for). The fix is on the
manager side and needs no restart: `zabbix_server -R snmp_cache_reload`. Both upgrade playbooks now
run it at the end via `ansible/zabbix-snmp-reload.yml` whenever a router rebooted onto a new package.

### 28.7 What this does *not* monitor — read this before trusting a green dashboard

The MikroTik MIB carries the platform. CPU, memory, disk, uptime, per-interface counters and errors.
Real value. It's the only layer of this fleet with history and it catches the slow failures nothing
else looks for: an interface whose error counter climbs for a week, a VPS neighbour eating the host, a
disk filling with logs.

**It doesn't carry BGP, OSPF or BFD session state.** Every check in §11 (adjacency counts, the BFD
session count, the anchor's `disabled` flag, advertisements toward each upstream) is unreachable over
SNMP on RouterOS. Those need a Zabbix SSH item or shipped syslog.

Said here because the failure mode is a familiar one. A fleet of green "Mikrotik by SNMP" dashboards
is evidence four *routers* are healthy. That's a different claim from the network being healthy, and
the difference is exactly the hard part of this network.

---
## 29. The pipeline — deployment gated on tests, not on a prompt

§18 put the rollout in Ansible. `reset-configuration` + `run-after-reset`, one router at a time,
alternating `br → er` so a border router and an edge router are always up, with a `pause:` before
each. That flow was correct and had one weak joint. **The gate was a human pressing ENTER**, and all
it verified was that the previous router still answered SSH and reported the right identity.

Me, at 1 a.m., pressing ENTER, is not a test suite. Who knew.

That's a smoke test and it passes on a badly broken router. The apply path wipes the box and replays
an add-only script. RouterOS stops at the first line it rejects and skips everything after it. A
config rejected on line 700 comes back, answers SSH, reports the right name and has no BGP at all.
The prompt asked whether you'd looked. It couldn't ask whether you'd looked at the right thing.

**Chosen:** the fleet's own topology generates the deployment pipeline, and the gate between routers
becomes a functional test expressed as a dependency edge.

- `.gitlab-ci.yml` validates, unit-tests and renders. The **rollout is a child pipeline that
  `generate.py` wrote** ([`emit.py`](emit.py)), one `deploy` + `verify` pair per router.
- `deploy:er1` **needs** `verify:br1`. A failing test doesn't stop a script. The next router's job
  just never becomes eligible to run.
- Merging to `main` deploys. The prompt is gone. `-e gate=auto` skips it and the default stays
  `manual` for anyone at a terminal.

Mechanism, setup and the full test inventory: [docs/netdevops.md](docs/netdevops.md).

### 29.1 The pipeline is generated, because the ORDER is the safety property

The alternating order is the one property that keeps the `/24` anchor and the `/25` from ever being
dark at the same time. Write it by hand as a job list and a third border router lands wherever
somebody appended it. Nothing in GitLab knows or cares.

So `deploy_order()` derives it from the same `build()` output that renders the configs, and the child
pipeline is emitted from that. Adding a router grows the fleet, the inventory, the assertion counts
and the pipeline's job list in one step.

Same argument retired `ansible/inventory.yml`. It listed `ansible_host` and `router_role` per router,
and both are **derivable from the role**. A BR is reached at its provider WAN (the only address it has
before the tunnels exist). An ER at its transit address (§25's break-glass, which survives every
tunnel being down). A site at its loopback. Two files describing one fleet is the drift this repo
exists to remove, and CI doesn't get an exemption.

What stayed hand-written is the job *bodies* ([`ci/child-jobs.yml`](ci/child-jobs.yml)). People skim
generated YAML, and the shell that resets a live border router shouldn't be in the part that gets
skimmed.

### 29.2 Private keys never enter the artifact store

`out/*.rsc` hold WireGuard private keys. The obvious pipeline shape (render once, pass the configs to
the deploy jobs as artifacts) copies them into GitLab's artifact store. There they sit for the expiry
window, downloadable by anyone with project access. §3's trust table says those files are never
committed. An artifact store isn't meaningfully better than a commit.

**Chosen:** the deploy jobs re-render. That's only safe if two things hold, so both are asserted on
every merge:

1. **The generator is deterministic.** Same topology, same keystore, byte-identical output.
   `tests/unit/test_determinism.py`.
2. **The build-time fetches are pinned.** The non-obvious half. `generate.py` reaches out to two URLs
   *while rendering*: the management SSH keys and the `mgmt_prefixes` endpoint. Fine when one person
   renders and immediately applies. In a pipeline that renders in one job and deploys in another, the
   second render can get a different answer, and then the config that ships **isn't the config that
   passed the tests**. Both renders are individually correct and nobody would ever notice.

`--pin` records what the fetches returned. `--use-pin` replays them and refuses a pin taken against a
different `topology.yml`. Every rollout job diffs its re-render against the build job's output before
touching a router.

The artifacts that do travel (`manifest.json`, `inventory.yml`, `pipeline.yml`, `pin.json`) carry no
key material, and `tests/unit/test_secrets.py` fails the build if that changes. WireGuard peer publics
show up as truncated SHA-256 fingerprints. Enough for a test to prove the running config carries the
intended peer, without the manifest becoming something you have to protect.

The same pinning makes the unit suite hermetic. A hard failure on an unreachable SSH-key endpoint is
correct behaviour (rendering with zero keys would clear the admin user's access and put nothing back)
but it also makes the generator unrunnable on a CI runner with no route to it. The tests write a pin
by hand and replay it. No stubbing, and the code path under test is the one production uses.

### 29.3 The end-to-end test runs on the runner, not on a router

Every check in `verify.yml` asks a router about itself. None can tell you whether anything behind the
firewalls reaches the internet, because the routers aren't where the customers are.

**Chosen:** put the runner at hdc, **behind the customer firewalls**, and make its own egress the
traffic under test. Then it isn't a simulation of the path. It *is* the path.

The assertion is that **the source address the internet sees is inside `203.0.113.0/24`**, and it's
stronger than it looks. It proves the *return* half independently of the outbound half. Traffic can
leave through anything, but it only comes back to our space if the prefix is in the DFZ, an anchor is
up, an upstream is carrying it and the tunnels deliver it home. A default leaked in from somewhere
else would still give you working internet. With a different source address. One HTTP GET, and it
runs after every router, not once at the end.

The second assertion is a multi-megabyte TLS transfer. §5's MSS clamp has a failure mode with no
symptom ICMP can see. Ping is flawless, DNS is instant, small requests work, and anything that fills a
window stalls forever. Nothing else in this repo had ever tested it.

So the runner's placement is a design constraint, not an ops detail. SSH to the routers is
source-filtered to `mgmt_prefixes`, so an off-site runner can't reach them at all. And an on-site
runner *outside* the firewalls would pass every test while proving nothing about the customers.

### 29.4 What the gate deliberately does not do: roll back

No automatic rollback. Adding one would be a mistake.

The apply path is destructive. Rolling back means rendering an older commit and running the **same
destructive apply again**, on a router that just showed it doesn't come back cleanly. One broken
router becomes two, unattended.

The pipeline **stops** instead. The remaining routers are untouched, the fleet keeps serving on them
and the failing job names the check that failed. Recovery is a human with the provider console open,
which §18 already made a prerequisite for running this flow at all.

That's the honest cost of auto-deploy on merge. A bad render reaches a live border router with nobody
watching. Between those two things stand the lint stage refusing to build it, the `baseline` job
refusing to start on an already-unhealthy fleet and the per-router gates stopping at the first router
that doesn't come back right. A lot more than the prompt gave you. Still not the same as being able to
undo it, and pretending otherwise would be the real error.

### 29.5 `chaos.yml` — asserting behaviour, and the deadman that makes it safe

[docs/failure-modes.md](docs/failure-modes.md) makes claims about what happens when an upstream, a WAN
or a firewall dies. `verify.yml` asserts **state**: sessions established, adjacencies Full, routes
present. State isn't behaviour. A network can sit in a perfectly healthy state and still fail to
converge when something's removed.

So `chaos.yml` removes it, asserts the *same* end-to-end test still passes and restores. Manual, never
automatic.

The part to write down is the **deadman**. Each scenario schedules its own undo on the router (a
`/system/scheduler` entry) before breaking anything and cancels it after restoring. An `always:` block
was the obvious answer and it isn't enough. `always:` runs when a *task* fails, not when the *process*
dies, and a test built to sever a network path is unusually likely to sever the path the restore
would've used. The undo has to live on the far side of the break.

### 29.6 Two validator gaps the tests found immediately

Writing `test_validation.py` against the **real** `topology.yml` (mutating one field at a time instead
of testing against purpose-built fixtures) turned up two addresses that were never checked at all. The
`home:` block seeded the duplicate-detection map without being checked against it, so:

- `transit_er2` set to `transit_er1`'s value just overwrote the label. Two edge routers, one address,
  rendered without complaint.
- A `transit_er*` outside `203.0.113.0/24` was never containment-checked.

Both render happily and fail on the wire. Every address now goes through one `note()` helper that does
containment and collision together, so a future block can't be added to the sweep as a seed without
also being subject to it.

That's the case for testing the validator against the live topology. A validator exercised only
against purpose-built inputs keeps passing while the fleet it guards grows features the fixtures never
had.

### 29.7 Ansible orchestrates, pytest asserts — and why not the REST API

The first cut put the functional checks in an Ansible playbook because the deploy was already there.
Wrong seam, and the reason for moving them isn't aesthetic.

**Where the line actually falls.** A deploy is ordering, waiting and retrying. Upload, reset, wait for
SSH to drop, wait for it to return, reboot, fingerprint. That's what Ansible is for. A check is an
assertion over structured data, and Ansible has no good way to express one. The probes were `:put`
expressions concatenating scalars into comma-separated strings, split back apart in Jinja. Two bugs
surfaced while writing them, both invisible until a router saw them. A folded YAML scalar silently
kept a newline that cut a RouterOS command in half, and a `regex_replace` backreference never
substituted. Neither could be caught offline.

**Chosen:** playbooks change things, `pytest tests/functional` checks them. The gate is
`pytest --router <fqdn> --focus <fqdn>` and it emits JUnit that GitLab renders per check. A failure
reads `test_ospf_adjacencies_are_full[br2.ord2]` in the UI instead of a wall of Ansible output. The
probe builder is ordinary Python, so `tests/unit/test_probes.py` asserts it offline on every merge.
Including "the probe is a single line", the bug that started this.

**Why not the REST API**, the obvious way to get structured data out of RouterOS 7:

1. **It's a listening service the templates disable by name.** `/ip/service` sets `www`, `www-ssl`,
   `api` and `api-ssl` to `disabled=yes` explicitly, with a comment saying why. The REST API needs
   `www-ssl` on. A new listener on a box whose `ether1` faces the DFZ, plus a self-signed certificate
   to pin or ignore. Widening a router's attack surface in order to check on it inverts the priority
   the whole `/ip/service` block was written around.
2. **The deploy path is irreducibly SSH and SCP.** Upload the `.rsc`, then
   `reset-configuration run-after-reset=`. REST can't do that cleanly, so the API would be a *second*
   transport with a second credential and a second ACL entry. And the failure mode is tests that
   can't reach a router the deployment can, or the reverse.
3. **You get the benefit without it.** `:serialize ... to=json` (RouterOS 7.13+) turns any
   `print as-value` into JSON. The fleet is on 7.24. So the probe gets structured data over the
   transport that already exists, in one round trip per router, with no new service.

The whole snapshot is one ssh invocation emitting `@@section <json>` lines, each wrapped in
`:do {...} on-error={...}`. That wrapper is there for a reason. An unknown property costs one section
and reports `PROBE-ERROR`, instead of returning an empty list every assertion downstream would read as
a dead network. "I couldn't ask" and "the answer is none" are different facts, and a gate that mixes
them up turns its own bugs into fake outages.

One thing `print as-value` won't give you. It returns only CONFIGURED properties, so
`/interface/wireguard/peers` has no `last-handshake` (and `print stats as-value` doesn't exist for
that menu). The handshake is the only liveness signal a WireGuard tunnel has, so it's fetched with an
explicit `get` per peer into a flat `iface=age` list. Building an array of dicts in RouterOS doesn't
work here. Named-key arrays MERGE on concatenation, so every peer collapses into one entry and the
last value wins.

### 29.8 `blackhole=no` matches nothing, and `anchor-guard` was using it

The functional suite found this on its first run against the live fleet. Best possible argument for
it existing.

RouterOS leaves a boolean property **unset** on rows where it doesn't apply instead of setting it to
`no`. So `find where ... && blackhole=no` matches **zero rows**, including every healthy route it was
written to find. The correct negation is `!blackhole`. Measured on br1 (7.24), with `203.0.113.0/25`
delivered by both edge routers:

```
/ip/route find where dst-address="203.0.113.0/25" && active && blackhole=no   ->  0
/ip/route find where dst-address="203.0.113.0/25" && active && !blackhole     ->  2
```

`anchor-guard` used the first spelling in its `delivered` loop (§7). So `delivered` was permanently
`0`, `agCustFail` climbed every tick, and at 60 consecutive failures the guard **withdraws
`203.0.113.0/24`**. The exact outage it exists to prevent, caused by the guard itself, about ten
minutes after anyone armed it.

Nobody noticed because the scheduler ships commented out and the README says to prove the anchor gates
origination before arming it. That check exercises the *withdraw* path, which worked perfectly.
Nothing exercised the *stay-up* path, which was the broken one. You can't validate a guard whose
failure mode is "withdraws when it shouldn't" by watching it withdraw.

**Fixed** in `templates/br.rsc.j2` (both families). Two tests now stand behind it.
`tests/unit/test_render.py` fails any rendered config with a `find`/`print` predicate comparing a
property to `no`. The pattern is checked against the buggy line, the fixed line and the legitimate
`output.network-blackhole=no` BGP property, so it catches the first and leaves the third alone. And
`tests/unit/test_probes.py` holds the same line for the test suite's own probe, which had the
identical bug and reported a live edge router's customer routes as absent.

Same lesson §29.6 already taught about the validator. This survived review because it reads correctly
in English, and it fails in the one direction nothing complains about. A silent zero.

### 29.9 Two SSH accounts, because people and machines have opposite key lifecycles

§15 made `ssh.keys_url` the single source of truth for who can log in. Keys are fetched at build time,
re-imported on every render and re-pulled on a schedule by `mgmt-refresh`. Exactly right for people.
Keys are device-tied, a laptop gets added, a phone retired, and the set is whatever the endpoint says
today.

Exactly wrong for a CI runner. A machine account has one keypair that changes when somebody edits a
file, and putting it behind an endpoint would make the rollout depend on a fetch at the moment it's
least wanted.

**Chosen:** a second account, `automation:` in `topology.yml`, with the opposite lifecycle. The public
half is **committed** and reviewed in a diff, not fetched. `ssh.user` stays the human one and nothing
about it changes.

Keeping them apart makes each revocable on its own. Delete the `automation:` block and deploy, and
CI's access is gone with every human login untouched. The reverse works too.

Sharing one account is refused by name, and not for tidiness. It **breaks**. The human import does
`/user/ssh-keys/remove [find user=...]` before re-importing, so every build would delete the runner's
key and CI would fail on the next deploy with a permission error you can't tell apart from an
unreachable router.

Committing the public half doesn't break §3's promise that `topology.yml` holds no secrets. A public
key is public by construction. The private half exists only as a masked, protected, File-type GitLab
variable, and `generate.py` refuses a `keys` entry containing `PRIVATE KEY` by name. Pasting the wrong
half of a keypair into a committed file is a one-keystroke mistake with a very long tail.

#### The group is narrower than `full`, and the reason is not least privilege

`automation.group` renders a RouterOS group from `automation.policies`: `ssh`, `ftp`, `read`, `write`,
`test`, `reboot`. Each is something the deploy or the tests actually do (`ftp` because RouterOS governs
SCP with it, `test` because `/ping` backs the loopback-mesh and MTU checks).

**Calling this least privilege would be dishonest.** The deploy primitive is `reset-configuration`. A
user that can wipe a router and reload it can install any config it likes, so `write` plus `ftp` is
already the whole farm. The narrower group closes every *other* door. `winbox`, `web`, `api`,
`rest-api`, `romon`, `sniff`, `sensitive`, `policy` and `password` are all absent, so a leaked runner
key can't open a GUI, drive an API, capture traffic, read secrets back out of `/export` or change
anyone's login. Defence in depth, not a boundary. Worth having on those terms only.

The policy vocabulary in `validate()` was read off a live 7.24 router's builtin groups, not the docs.
An unknown policy name makes `/user/group/add` fail and that line runs on a box `reset-configuration`
already wiped. Same reasoning makes the six required policies a hard check. A missing one fails partway
through a rollout, and where it fails decides how bad it is. `scp` failing is harmless. `reset` failing
is harmless. A missing `read` fails the verify gate on a box that's already live.

Both the group and the user are rendered **set-if-present**, not add-only. Editing `group:` has to MOVE
an existing account. An add-only line would silently leave it where it was and the config would
disagree with the router forever.

#### The bootstrap, and why it cannot be automated away

The account doesn't exist on a router until a config creating it is applied, and the runner can't
apply that config because the account doesn't exist. A workstation that already has access breaks the
loop once (paste the public key, `./build.sh`, `ansible-playbook deploy.yml`) and after that the runner
is autonomous.

A real one-time manual step with no way around it that doesn't amount to trusting something else
first. It's also the only one. CI reads `automation.user` out of `manifest.json`, so the account is
named in `topology.yml` and nowhere else.

### 29.10 A border router's public address is unreachable from inside our own /24

CI's first `baseline` run couldn't open TCP/22 to either border router, while the workstation that had
been driving the fleet all evening could. Both sourced from addresses in `mgmt_prefixes`. The
difference was which side of the AS they stood on. A latent design fault the pipeline just walked into
first.

Measured on the live fleet:

```
er1 -> 198.51.100.57/32  via 172.20.101.1%ether1   (static)
br1 -> 203.0.113.7      via wg-er2-wan1           (iBGP, dist 200)
br1 -> 192.0.2.190       via 198.51.100.1%ether1   (default)
```

The ERs carry a static `/32` for each BR's public address pointing out their own WAN. That route isn't
optional. A WireGuard endpoint must never resolve through a tunnel, or the tunnel's outer packets
route into the tunnel and it flaps forever (same reasoning as `sibling_publics` on the BRs, §5). So a
request from inside leaves via the ISP.

The BR then answers using the `/25` it learns over iBGP. Back down a tunnel. Request out one path,
reply down another, and the handshake never completes.

The third line is the control. An address OUTSIDE our space has no specific route on the BR, falls
through to the provider default and comes back the way it arrived. That's why every manual session
from the workstation worked and nothing from the runner did.

**Chosen:** inside the AS, address a border router at its LOOPBACK. `ansible_host` in the generated
inventory is now the in-AS address. The provider WAN moves to `bootstrap_host`, reached with
`-e use_bootstrap=true` or `--bootstrap`.

Three reasons this is the right answer and not a workaround:

- **The BR isn't misrouting.** Answering an in-AS source down a tunnel is correct. The alternative is
  out to the internet and back in through our own announcement. The asymmetry comes from the request
  leaving the other way, and that static `/32` has to stay. Nothing here should be "fixed" on the
  router.
- **The loopback is the address that belongs to the AS.** The public address exists for control nodes
  that aren't in it. Reaching for it from inside was the category error.
- **It adds a gate.** Reachability at the loopback IS proof the tunnels came up and OSPF converged.
  Every deploy now has to show that before the rollout moves on. The WAN address silently skipped it,
  because a border router with every tunnel dead still answers on its provider WAN.

The failsafe stays, and stays documented. A BR whose tunnels are down is reachable at
`bootstrap_host`, and if neither address works the answer is the provider console. §18 already
required anyone running this flow to have it open.

Said plainly, because it was invisible while there was only one control node: `mgmt_prefixes` ships
`203.0.113.0/24` as its committed floor. That advertises management-from-inside as a supported path.
For the BRs' public addresses it never was.

---
## 30. Origination mode — a per-BR drain lever that fails closed

*For the days a provider is perfectly fine on paper and a disaster in practice.*

**Context.** A provider can have trouble with *our* traffic while its BGP session to us stays up.
Lossy peering, a broken path toward home, a scrubbing platform misbehaving. Anchor-mode origination
(§2, §6.5) rides that out on purpose. A BR that can't reach home over its own WAN keeps its iBGP
sessions over the backbone (mechanism 3), keeps the `/25`, keeps announcing and keeps attracting
traffic it can only deliver the long way, if at all. The documented kill switch (§10) is disabling the
eBGP session on that BR. Which means getting a shell on a box whose provider is the problem.

The lever the operator actually holds during that event is at home: the ERs' tunnels to that BR. In
anchor mode pulling them does nothing to the announcement. That's mechanism 3 doing its job.

**Chosen:** `origination.mode` in `topology.yml`, `anchor` (default, unchanged) or `home`. Home mode
keeps the anchor, `output.network`, the script and the instant re-origination. It changes only
`anchor-guard`'s customer signal, which becomes: the home `/25` (and `/48`) is active and its
`immediate-gw` names one of **this BR's own ER tunnels**. The timer is 6 ticks (60 s, the isolation
timer) instead of 60. A `/25` resolving through the backbone reads `%wg-<sibling>` and doesn't count.

Arming moves into `topology.yml` too (`origination.arm_guard`). Until now arming meant pasting the
scheduler onto a box, and the next `reset-configuration` deploy silently undid it. For a mode whose
whole point is that the guard runs, an arming step that doesn't survive a deploy isn't an arming step.

**Rejected:**

- **Single-hop iBGP over the tunnel /31s**, so a dead tunnel literally drops the session. Matches the
  mental model of "disable the tunnels and BGP to that BR goes down". But it rebuilds the whole mesh
  (four sessions per BR per ER, next-hops no longer loopbacks) to get a signal one script line can
  read.
- **A static `/24` with `check-gateway` at the ER tunnel addresses.** No script, but the anchor stops
  being a blackhole and starts forwarding unclaimed space to the ERs. `check-gateway=bfd` on a static
  route is also another property nobody has run on this fleet, and it sits on the import path instead
  of inside a script body that can't abort an import.
- **Counting OSPF neighbours on the home tunnels.** Closer to "is the tunnel up" than "does home reach
  me". The intent is the second: the ERs' own advertisement, delivered directly.

**Consequences:**

- A home outage longer than 60 s withdraws the `/24` from every BR. The "Before" column of §1, chosen
  knowingly. Remote sites no longer hold the prefix up. Costs nothing while `sites: []`, and must be
  revisited when the first site goes live.
- It fails **closed**, which is what disqualified the community-signal idea (§9.2). If the control
  path dies the BR withdraws instead of un-suppressing itself.
- It doesn't fight `anchor-guard` (§10's corollary) because it *is* `anchor-guard`. Nothing touches
  the anchor route except the guard.
- **Unverified on a live box:** `immediate-gw` as a `find` predicate, and its `<addr>%<iface>` form for
  iBGP routes resolved through OSPF. Both appear in RouterOS v7 `print detail` output but this fleet
  hasn't run either in a script. The proof sequence is rendered above the scheduler line in each
  `br*.rsc`. Run it before `arm_guard: true`. If the first print is empty with the tunnels up, the
  guard would withdraw the `/24` from every BR 60 s after arming. The §29.8 failure in a new form.
