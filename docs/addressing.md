# Addressing and naming

The whole network lives inside `203.0.113.0/24`. Everything below is *derived* from a small plan in
`topology.yml`. Nothing is listed by hand. If you're hand-editing a `/31` something went wrong (see
[`generator.md`](generator.md#why-not-a-flat-env)). This doc is the map.

## The `/24` carved up

| Block | Use |
|---|---|
| `203.0.113.0/25` | Home customer space. eBGP customer firewalls (fwa) claim VIPs here. **The ERs advertise it into iBGP** as an aggregate. |
| `203.0.113.128/27` | Remote-site delegations (4 × `/29`). Site *n* gets `128 + (n-1)*8` and the router holds the first usable address as the inside gateway. **Attached, not routed onward.** No NAT, no customer eBGP. |
| `203.0.113.160/28` | BR↔BR backbone `/31`s |
| `203.0.113.176/28` | Remote-site tunnel P2P `/31`s. **This block caps the whole site design.** 8 `/31`s and a site takes one per BR. 4 sites × 2 BRs fills it exactly. A third BR overflows it and `generate.py` refuses to render. |
| `203.0.113.192/27` | BR↔ER tunnel P2P `/31`s (16 tunnels) |
| `203.0.113.224/28` | ER interconnect + firewall transit `/29` (no VRRP) |
| `203.0.113.240/28` | Loopbacks |

### Loopbacks — canonical router addresses

A router's loopback *is* its canonical address. BGP and OSPF router-id, iBGP peering address and
what the bare router name resolves to in DNS.

| IP | Router |
|---|---|
| `.241` | `br1.ord1` (Vultr) |
| `.242` | `br2.ord2` (HostHatch) |
| `.243` / `.244` | br3 / br4 (future) |
| `.245` – `.248` | remote-site routers, `sr1.<site>`, by site index 1–4 |
| `.249` | `er1.hdc` |
| `.250` | `er2.hdc` |

Three contiguous runs: `.241-.244` border, `.245-.248` site, `.249-.252` edge. You can read a
router's role off its loopback and no two families can grow into each other.

## Naming convention

Names describe **role**. Never **media** or **geography**. Changing ISPs, swapping fibre for coax
or moving a rack should never force a rename.

| Element | Convention | Examples |
|---|---|---|
| **Site** | 3–4 char code, no geography implied | `hdc` (home DC), `ord1` (Vultr), `ord2` (HostHatch), `sfo` (remote site) |
| **Router** | `{role}{n}.{site}` | `br1.ord1`, `er1.hdc`, `sr1.sfo` |
| **Roles** | `br` border · `er` edge · `sr` site router | a `sr` is an edge router for one site: one box, one WAN, tunnels to every BR |
| **Home WANs** | `wan1` = primary, `wan2` = backup | today wan1 = Comcast and wan2 = 5G, but nothing depends on that. Both are NAT'd. Neither has a public address |
| **Tunnel interface** | named for the **far end**, from the local device's view | on `er1`: `wg-br1-wan1`; on `br1`: `wg-er1-wan1`; on `sr1.sfo`: `wg-br1`, and `wg-sfo` on the BR |
| **Interface lists** | `tun-wan1`, `tun-wan2`, `tun-bb`, `tun-site`; `tunnels` = all | used by the firewall, OSPF and BFD templates |
| **Routing tables** | `via-wan1`, `via-wan2` | the ER (and site) egress-pinning marks |
| **Site LAN** | `br-lan` bridge over the non-WAN ports | holds the `/29` gateway; DNS `br-lan.sr1.sfo` |

The payoff: **WAN preference is only OSPF cost** (wan1 = 10, wan2 = 100). Never BGP, never a name.
Promoting wan2 to primary is a two-line cost change. And a `traceroute` through the AS reads like a
description of the path because interface DNS names mirror interface names exactly
(`{interface}.{router}.{site}.example.net`).

Two decisions *do* depend on what the home WANs physically are. **Neither has a public address.**
wan2 is CGNAT'd and wan1 has been a static private address on the ISP gateway's LAN since the
Comcast block was dropped (AD-LOG §25). So WireGuard is mandatory and the ER must initiate on both.
And wan2 is *jittery*. That's the one asymmetry left: looser OSPF timers and no BFD. See
[wireguard.md](wireguard.md) and [ospf.md](ospf.md).

wan1 being static on a private LAN instead of DHCP has one consequence. `address` and `gateway`
stay in `topology.yml` so the BR-public `/32` pins in `er.rsc.j2` still render. Under a dhcp-client
they'd vanish, which is safe since the mangle/srcnat pair is what really pins the outer flows. But
that's why the ER config has the same shape either way.

## DNS — `example.net`

Three rules do most of the work:

- **The bare router name resolves to its loopback.** Interface addresses get
  `{interface}.{router}.{site}.example.net`.
- **No DNS names in router configs.** BGP, OSPF and `anchor-guard` all use literal IPs. A DNS
  outage must never touch routing.
- **Don't host both nameservers inside `203.0.113.0/24`.** If the network is down your DNS goes
  with it, along with the PTRs you'd want while debugging. Keep at least one authoritative NS
  off-net.

### The reverse DNS you actually need

A `traceroute` *into* your AS shows the **provider WAN IPs** (`198.51.100.57` for br1, the
HostHatch IP for br2). So do abuse reports and mail headers. You set their PTRs in the **provider
panel** because you don't own them. Get those right before any record in your own zone. The
`/24`'s reverse zone (`113.0.203.in-addr.arpa`) is delegated from ARIN against your net handle.

Full per-address DNS tables (every tunnel `/31`, backbone link and home local link) are in
[AD-LOG.md §5](../AD-LOG.md). This doc is the summary. That section is the exhaustive list.
