# Layer 0 — WireGuard underlay

Every router-to-router link in AS64500 is a WireGuard tunnel. No unencrypted internal transport
anywhere. The tunnels are the wires OSPF and iBGP run over.

## Why WireGuard, and why it isn't optional

The home edge routers sit behind consumer WANs and **neither one has a public IP any more**. `wan2`
is CGNAT'd. `wan1` used to be a static Comcast address. That block was dropped and it's now a
private address on the ISP gateway's own LAN, NAT'd by the gateway (AD-LOG §25). No public IP and
no inbound port on *either* WAN. Two consequences follow and they're the whole reason the
transport looks like this:

(Residential internet: where "static IP" is a monthly fee and a mood.)

- **GRE/IPIP can't traverse NAT** and a datacenter BR can't open a connection *toward* a NAT'd home
  router. So the tunnels have to pierce NAT and **the ERs always initiate. Every WAN, no
  exceptions.** You can see the asymmetry in the config:
  - ER peer stanzas carry an `endpoint-address` (the BR's public IP) and `persistent-keepalive=25s`.
  - BR peer stanzas toward the ERs carry **no endpoint**. The BR waits to be called and learns the
    ER's current address from whatever packet arrives.
- The **BR↔BR backbone** links run between two public datacenter IPs so those peers *do* carry
  endpoints on both sides.

This used to rest on `wan2` alone being CGNAT'd, with `wan1`'s public static as the escape hatch.
The escape hatch is gone. Now it's **unconditional**. No ER WAN answers when a BR dials, so don't
build anything that assumes one might. Not now and not later.

Two things depend on this. `persistent-keepalive=25s` on every ER peer is the only thing keeping
the gateway's NAT binding open between packets. And the `srcnat` masquerade on every WAN is what
lets the source address survive the NAT at all (see the mangle/srcnat pair below, and §23).

## How a tunnel is named

Interfaces are named for the **far end, from the local device's view**. On `er1` the tunnel to
`br1` over the primary WAN is `wg-br1-wan1`. The matching interface on `br1` is `wg-er1-wan1`. A
`traceroute` through the AS reads like a description of the path, and changing an ISP or medium
never forces a rename. Names describe **role**. Never geography or media.

## The port convention carries the WAN

An ER reaches each BR over **both** WANs, so two tunnels between the same ER and BR land on the
**same BR public IP**. WireGuard tells them apart by **destination port** and the port says which
WAN the tunnel belongs to:

| Tunnel family | BR listen port | Notes |
|---|---|---|
| `er*` via **wan1** | `518xx` | `51821` = er1, `51822` = er2 |
| `er*` via **wan2** | `519xx` | `51921` = er1, `51922` = er2 |
| BR↔BR backbone | `51100 + y` | On `brx` the interface facing `bry` listens on `51100+y`. Scales to br5/br6 with no renumbering |
| remote **site** | `520xx` | `52021` = site1, `52022` = site2. The port encodes the **site** so every BR listens on the same one for a given site. A site has one WAN, so there's no WAN to encode |

Encoding the WAN in the port is what lets the ER's egress policy tell the two tunnels apart. A
packet for `518xx` gets pinned to wan1 and `519xx` to wan2. See [ospf.md](ospf.md) and the ER
mangle rules in [`templates/er.rsc.j2`](../templates/er.rsc.j2) for how the pinning works
(`chain=output` routing marks that never touch the transit fast path).

**Pinning the egress takes two rules. Not one.** The routing mark picks the *interface*. It
doesn't pick the *source address*. RouterOS assigns that out of `main` at the routing decision
**before** `mangle output`. So a marked packet leaves the right interface with the wrong WAN's
address, the tunnel goes one-way and every symptom points at the carrier. Each WAN gets a matching
`chain=srcnat` masquerade on the same port range. It runs late enough to see the interface the
mark actually picked. Both rules come as a pair from one derived range (`wan_port_base` in
`generate.py`) so you can't add one without the other. AD-LOG §23 has the diagnosis and §23.5
explains why NAT is safe on a router whose transit is `notrack`ed.

## MTU is a single global constant

Every tunnel uses the same MTU (`wg_mtu: 1360`). Not cosmetic. A flow that fails over from wan1 to
wan2 mid-stream would blackhole if the two paths had different MTUs, and **you can't fix that after
the fact**. The TCP MSS option only appears in the SYN (RFC 9293 §3.7.1) and can't be renegotiated
mid-connection. One global MTU makes failover MTU-transparent. So no per-circuit MTU tuning, however
much headroom the fibre path has.

**The clamp is one value per family.** MSS is the payload left after the headers the tunnel carries
and the IPv6 header is 40 bytes where IPv4's is 20:

| Inner family | Clamp | Derivation |
|---|---|---|
| IPv4 | 1320 | `wg_mtu - 20 (IPv4) - 20 (TCP)` |
| IPv6 | 1300 | `wg_mtu - 40 (IPv6) - 20 (TCP)` |

`mss_clamp` lives in `topology.yml`. `mss_clamp_v6` is derived. The generator enforces both and
refuses to render otherwise. Clamp v6 to the v4 number and every large segment is 20 bytes over the
tunnel MTU. The flow then only completes if ICMPv6 Packet Too Big reaches the sender, which is the
exact dependency the clamp exists to remove. And v6 routers can't fragment as a fallback.
**Measure your worst underlay before trusting 1360.** 5G links often give you less than 1500. See
[`generator.md`](generator.md#validation-runs-before-anything-is-written).

## Post-quantum hardening: the pre-shared keys

Every WireGuard peer carries a unique 32-byte `preshared-key` on top of its X25519 keypair. Both
ends of a tunnel share the same PSK. `generate.py` generates them and stores them in `keys.json`.

WireGuard's Noise `IKpsk2` handshake mixes the PSK into key derivation. Someone who records today's
handshakes and later breaks X25519 with a quantum computer **still** can't derive the session keys
without also stealing the symmetric PSK. It costs one extra HKDF round. No latency, no runtime cost.
`--rotate-keys` regenerates the PSKs with the keypairs. The PSK is a *second independent* secret. It
doesn't replace the keypair.

## Key management

Keys cross-reference. `br1`'s peer stanza needs `er1`'s **public** key and vice versa, on every
tunnel, on both ends. That graph (18 keypairs today, 44 at four BRs) is why the config is generated
and not hand-written. Generation is idempotent. A re-run never regenerates an existing key, which
would quietly break every peer. Adding a router only mints keys for its new interfaces. See
[`generator.md`](generator.md#key-generation-is-idempotent-on-purpose).

---

**Next layer:** [OSPF →](ospf.md). The only thing that notices when one of these tunnels dies.
