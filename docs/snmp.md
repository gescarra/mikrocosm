# SNMPv3 — the read-only monitoring plane

Everything on this fleet that *acts* on a failure runs on the routers themselves.
[`anchor-guard`](origination.md) withdraws the aggregate. `home-anchor-guard` withdraws the `/25`.
`default-guard` stops originating a default a BR can't honour anymore. OSPF+BFD tear the adjacency
long before any of them notice. None of that needs a monitoring system and none of it should.

Monitoring is for the other half. Knowing something **quietly degraded** instead of failed, and
having a year of history when you go looking for when it started.
[AD-LOG §11](../AD-LOG.md#11-monitoring) lists what to watch. This page is how the data gets out.

**One v3 user, authPriv, read-only, polled by Zabbix. No v1, no v2c, no traps.**

---

## The three locks

Independent on purpose. Any one failing open leaves the other two holding.

| # | Lock | Where it lives | What it stops |
|---|---|---|---|
| 1 | `snmp.sources` → `add chain=input action=accept protocol=udp dst-port=161 src-address-list=snmp` | the input chain of every router, above the terminal drop | Anyone but the poller sending this router an SNMP packet **at all**. This is what `topology.yml` asks you for. |
| 2 | `security=private` (authPriv): SHA auth + AES encryption | `/snmp/community` | A poller that doesn't know both passphrases, and anyone watching the path. The whole PDU is encrypted, not just the credential. |
| 3 | `read-access=yes` / `write-access=no` | `/snmp/community` | SNMP changing the router. On RouterOS that's literal: `snmpset` to `1.3.6.1.4.1.14988.1.1.7.1.0` **reboots the box**. |

A fourth thing happens whether or not you ever enable SNMP. RouterOS ships a community named
`public` with `security=none`, and the generated config sets `read-access=no` on it on every
router. An agent answering `public` on a CHR whose `ether1` faces the DFZ isn't an information leak.
It's a UDP amplifier with someone else's name in the return address.

---

## What gets rendered, and where

Three places. The split is on purpose:

| Rendered | Where in the `.rsc` | Why there |
|---|---|---|
| `/ip/firewall/address-list` entries for `snmp.sources`, `comment="snmp-poller"` | `_mgmt.j2`, next to the `mgmt` list, near the top | Address lists should exist before the rules that name them. It sits beside `mgmt` so you compare the two on one screen. |
| the `udp/161` accept | each template's own input chain | Its position relative to the terminal `drop` is the only thing that makes it work. That has to be visible on the page, not hidden in an include. |
| `/snmp/community` + `/snmp set` | `_snmp.j2`, **last line of the file** | See below. |

### Why the agent config is last

`/import` is strictly ordered and this deploy path runs it right after `reset-configuration`
([generator.md](generator.md)). A line RouterOS rejects doesn't just fail. It abandons every line
*below* it on a box that's already been wiped.

Two properties here take different values on different RouterOS versions:
`authentication-protocol` and `encryption-protocol`. MikroTik documents `MD5|SHA1` and `DES|AES`.
Newer builds take `SHA256`/`SHA512`. Raise either and if your version disagrees the import dies at
that line. So it's the last line in the file. **Get it wrong here and you lose monitoring, which you
notice from outside. Anywhere else you'd lose the firewall, which you wouldn't.**

Verify before you raise it. One line, reversible, touches nothing else:

```
/snmp/community/set [find name=zabbix] authentication-protocol=SHA256
```

---

## `mgmt` and `snmp` are different lists, deliberately

Every input chain accepts everything on `mgmt` **wholesale**. Every protocol, every port, SSH and
Winbox included. The poller needs `udp/161` and nothing else.

A monitoring server is the one box that talks to every router. *And* it's a web app with users,
plugins, a database and a browser-facing login. Putting it on `mgmt` trades the fleet's whole
management surface for one saved line of config. It gets its own list.

---

## Rolling it out

Two passes. Same discipline as [BFD](../AD-LOG.md#19-bfd--sub-second-liveness-under-ospf) and
`mgmt_refresh`, because `ansible/deploy.yml` applies one router at a time behind a manual gate and
for a long window half the fleet has the new config.

**Pass 1: `enabled: false`, deploy everywhere.** Renders `/snmp set enabled=no` explicitly and
neutralises `public`. Nothing starts listening and no credential lands in any `.rsc`. Worth doing
for the hardening alone.

**Pass 2: fill in `snmp.sources`, `enabled: true`, deploy everywhere.** Armed.

In between, from the poller itself, against **one** router:

```
snmpwalk -v3 -l authPriv -u zabbix -a SHA -A '<auth>' -x AES -X '<priv>' \
         203.0.113.241 1.3.6.1.2.1.1.5.0
```

It should come back with the router's identity (`br1.ord1`). **Times out?** Suspect the firewall.
Check the address the router sees is the one in `snmp.sources`:

```
/ip/firewall/address-list/print where list=snmp
/log/print where topics~"firewall"
```

**Authentication failure?** The credentials or the protocol names disagree. `snmpwalk` naming the
wrong algorithm and Zabbix naming the wrong one look identical from here.

`snmpwalk` from the poller **works** but Zabbix **times out**? Especially if exactly one router
works and the rest don't. Not the firewall. It's the engine-id. See
[One engine-id per router](#one-engine-id-per-router).

### One engine-id per router

RouterOS does **not** give each device its own engine-id. With `engine-id-suffix` empty (the
default) every MikroTik reports `80003a8c04`: the enterprise number, the text-format marker and
nothing after. Measured on 7.24.5 on all four routers at once.

SNMPv3 keys its replay protection (engineBoots and engineTime) by engine-id. Zabbix polls four
agents claiming the same identity, keeps the clock of whichever answered first and throws away
every other router's reply as outside the time window. The UI says `Timeout while connecting` so it
looks just like a firewall drop. **The tell is one host working and every other one failing.** The
`snmpwalk` above won't catch it because a one-shot CLI process starts with an empty cache every
time.

`_snmp.j2` sets `engine-id-suffix` to the router's FQDN (`br1.ord1`, `er2.hdc`, …). Already unique
across the fleet, survives a CHR rebuild, and `/snmp print` then tells you which box you're on.
`generate.py` refuses a name longer than the 27 octets an engine-id has room for and refuses two
routers sharing one.

**After changing any router's engine-id, restart `zabbix-server`** (and any proxy polling it). It
caches engine state in memory. Until it forgets the old one the fix looks like it did nothing.

---

## Zabbix

Every build with SNMP armed writes `out/snmp_zabbix.env`. The credentials **under Zabbix's own
macro names**, because Zabbix is the one place you have to type them a second time:

```
SNMP_USERNAME, SNMP_SECURITYLEVEL, SNMP_AUTHPROTOCOL,
SNMP_AUTHPASSPHRASE, SNMP_PRIVPROTOCOL, SNMP_PRIVPASSPHRASE
```

Define them as **global macros** (Administration → Macros. Global, because the whole fleet shares
one user). Give each router a host with an **SNMP interface** set to SNMPv3 and reference the macros
in the interface's fields (`{$SNMP_USERNAME}`, `{$SNMP_AUTHPASSPHRASE}`, `{$SNMP_PRIVPASSPHRASE}`,
…). Then attach the stock **Mikrotik by SNMP** template. These are Zabbix's own SNMPv3 macro names
so anyone who's done this before won't need this page. Adding the next router is a host with an
interface and nothing else to type.

**The interface fields and what RouterOS calls each one.** Every mismatch here fails the same way:
no data, no useful error, indistinguishable from the firewall dropping you.

| Zabbix field | RouterOS | Value here |
|---|---|---|
| **Security name** | `/snmp/community name=` | `zabbix` (`snmp.user`). The v3 *user*, not a community string |
| **Context name** | *(doesn't exist)* | **empty**, see below |
| **Security level** | `security=private` | authPriv |
| **Authentication protocol** | `authentication-protocol=SHA1` | SHA1 |
| **Privacy protocol** | `encryption-protocol=AES` | **AES128** |

`generate.py` already writes the translated values into `out/snmp_zabbix.env` so the file is right.
This table is for when you're typing into the UI and it doesn't work.

**Leave context name empty.** RouterOS doesn't implement SNMPv3 contexts. `/snmp` has `contact`,
`location`, `engine-id`, `src-address`, `vrf` and the trap settings and nothing else. Every router
answers only in the default empty context. Type a context name into that field and it's sent in the
PDU, the agent replies with a report PDU for an unknown context and Zabbix shows no data. No error
naming the context. Reads exactly like a dropped packet, which is the wrong place to start looking.

**Poll the loopback.** Never a WAN or a tunnel address:

| Router | Poll |
|---|---|
| `br1.ord1` | `203.0.113.241` |
| `br2.ord2` | `203.0.113.242` |
| `er1.hdc` | `203.0.113.249` |
| `er2.hdc` | `203.0.113.250` |

The loopback is the one address that survives any single link failing, and `/system/identity`, the
DNS records and `out/snmp_zabbix.env` already agree on it. Poll a WAN address instead and an
interface flap looks like a dead router. The exact false positive that teaches people to ignore the
alert.

### What SNMP will and won't tell you

The MikroTik MIB gives you the platform. CPU, memory, disk, uptime, per-interface counters and
errors, CHR health. Nothing else on this fleet records that layer over time and it catches the slow
problems: a tunnel whose error counter climbs for a week, a VPS neighbour eating the CPU, a disk
filling with logs.

**It doesn't carry BGP, OSPF or BFD session state.** Nothing in
[AD-LOG §11](../AD-LOG.md#11-monitoring) is reachable over SNMP on RouterOS: adjacency counts, the
BFD session count, the anchor's `disabled` flag, advertisements toward each upstream. Those want a
Zabbix SSH item, or syslog shipped off the box and alerted on. A green "MikroTik by SNMP" dashboard
isn't evidence routing is healthy. It's evidence the *router* is healthy. Different claim.

---

## The credentials

**Not** in `topology.yml`, the file that promises no secrets. They're generated once into
`keys.json` (mode 0600, gitignored) under `snmp:<user>` like the WireGuard keys and reused on every
build. See [key generation is idempotent](generator.md#key-generation-is-idempotent-on-purpose).

32 URL-safe characters each. The alphabet isn't an accident. `A-Za-z0-9_-` can't contain the `"` or
`\` that would break out of the quoting in the `.rsc`. And breaking out of a quote in a file applied
by `/import` after `reset-configuration` isn't a syntax error. It's a router.

**One user for the whole fleet, not one per router.** Per-router passphrases would mean two host
macros per host kept up by hand. For a credential that's read-only, source-restricted and useless to
anyone who can't already reach `udp/161` from the poller's address. Buys almost nothing and you pay
every time you add a router.

**Rotating them is `--rotate-keys` and it isn't free.** That regenerates *every* key in the store,
WireGuard included. To rotate only SNMP, delete the `snmp:<user>` entry from `keys.json` and
rebuild. The next build makes a new pair, leaves every tunnel alone and writes a fresh
`out/snmp_zabbix.env`. Update Zabbix in the same window. Until you do every host goes unreachable at
once and no log says why.

---

## Why no traps

`trap-target` stays at its `0.0.0.0` default. This agent never sends anything unasked.

A v3 trap needs the **receiver** taught each router's engine-id. Per-router state to maintain, in
exchange for duplicating data Zabbix already polls every minute. The events worth waking someone for
(`anchor-guard`, `default-guard`, `mgmt-refresh`) go to the log with `:log warning`. Shipping the log
is one syslog target. No engine-ids involved.

`engine-id` is **not** left alone though. See [One engine-id per router](#one-engine-id-per-router).
