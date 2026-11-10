# Router rollout (Ansible)

**Ansible orchestrates, pytest asserts.** Everything here CHANGES something. The checks live
in `pytest tests/functional`. Assertions want structured data and a JUnit report, and the
probes read RouterOS over this same SSH path with `:serialize to=json`. See
[`docs/netdevops.md`](../docs/netdevops.md).

| Playbook | What it does | Changes anything? |
|---|---|---|
| [`deploy.yml`](deploy.yml) | Roll the generated config onto each router, one at a time | **Yes. Resets and reboots** |
| [`chaos.yml`](chaos.yml) | Break a live path on purpose, prove the failover, put it back | **Yes, temporarily** |
| [`upgrade.yml`](upgrade.yml) | RouterOS package + firmware upgrades | **Yes. Reboots** |
| [`upgrade-npk.yml`](upgrade-npk.yml) | Push a pinned RouterOS `.npk` from the control node | **Yes. Reboots** |
| [`zabbix-snmp-reload.yml`](zabbix-snmp-reload.yml) | Flush Zabbix's SNMPv3 engine cache (runs at the end of both upgrades) | No. Zabbix re-discovers |

```bash
pytest tests/functional                                       # the whole fleet
pytest tests/functional --router br1.ord1 --focus br1.ord1    # one router + cross-check
```

The GitLab pipeline drives all of it too. Everything CI does is one of these commands.

> **The inventory is generated.** `ansible.cfg` points at `../out/inventory.yml`, which
> `generate.py` writes from `topology.yml` on every `./build.sh`. `ansible_host` and
> `router_role` are both derivable (a BR is reached at its LOOPBACK, an ER at its transit
> address, a site at its loopback), so keeping them by hand was two sources of truth for one
> fleet. Operational variables (SSH options, timeouts, `router_user`) live in
> [`group_vars/all.yml`](group_vars/all.yml), committed. They're decisions about driving a
> rollout, not facts about the topology.
>
> `inventory not found` means the build hasn't run. Right error. There's nothing to deploy
> either.

---

Pushes the generated `out/<fqdn>.rsc` configs onto the border and edge routers over SSH
with the documented **reset-and-restore** flow from the repo
[`README.md`](../README.md#quick-start):

```
scp out/<fqdn>.rsc  ->  router
/system/reset-configuration no-defaults=yes skip-backup=yes keep-users=yes \
    run-after-reset=<fqdn>.rsc
```

It deploys **one router at a time** in this order, pausing for manual confirmation before
each:

```
br1.ord1  →  er1.hdc  →  br2.ord2  →  er2.hdc
```

Alternating border/edge keeps one border router **and** one edge router up at every step.
The `/24` anchor and the `/25` are never both dark at once.

---

## ⚠️ Read this before you run it

The repo README is blunt: this reset flow is meant to be driven from the **provider console
/ VNC**, because:

- `reset-configuration` **drops all connectivity and reboots**.
- You only get SSH back **if the generated script runs cleanly** and re-creates
  SSH-on-mgmt. If it errors partway, the box is reachable **only via console**.

Doing it over SSH (what this playbook does) is supported. The templates keep SSH on for
exactly this. But when it fails you're **locked out**. So:

- **Have the provider console/VNC open for each box before you gate it.**
  HostHatch VNC: [`docs/chr-vps-guide.md`](../docs/chr-vps-guide.md).
- The playbook waits for SSH to go **down** then **back up** and verifies the identity, so a
  silent no-op or a half-applied config gets caught instead of assumed good. It does **not**
  replace your own BGP/OSPF/anchor checks between steps.

Two things that quietly break an SSH rollout. Both handled here, but know them:

1. **SSH is source-filtered to `mgmt_prefixes`** in both templates (today one entry,
   `203.0.113.0/24`). Run this from the home site (a source IP in that `/24`) or every
   connection times out. The BRs are reached at their public WANs but still only accept
   sources from the `/24`.

   The **ERs are the exception.** They're reached on their transit addresses
   (`203.0.113.233`/`.234`) and the ER input chain accepts by *interface*
   (`in-interface=<transit>`) ahead of both the `mgmt` accept and the WAN drops. That path
   holds with every tunnel down and BGP dead. That's why it replaced the Comcast static as
   break-glass when `wan1` moved onto the ISP gateway's private LAN (AD-LOG §25).
2. **The reset regenerates the router's SSH host key.** The playbook uses
   `StrictHostKeyChecking=no` + `UserKnownHostsFile=/dev/null` so the post-reset reconnect
   doesn't choke on a changed key.

---

## Prerequisites

- `ansible-core` and an OpenSSH client on the control node.
- Configs generated: run `./build.sh` at the repo root so `out/*.rsc` exist.
- Control node on / sourced from `203.0.113.0/24` (see above).
- **Auth:** SSH key auth to the router user (default `admin`). `keep-users=yes` keeps the
  account across the reset. If the generated script re-adds your SSH *public key*, key auth
  keeps working through the reset. Otherwise see the password fallback below.

## Run it

```bash
cd ansible

ansible-playbook deploy.yml --check     # PLAN: which routers would be reset
ansible-playbook deploy.yml             # deploy only routers whose config changed
```

`--check` reads each device's stored fingerprint, compares it to a fresh render, prints
`WOULD BE RESET` or `unchanged` per router and **stops before the first destructive task**.
Same thing the pipeline's `plan` job posts on a merge request.

Override the login user or timeouts on the command line:

```bash
ansible-playbook deploy.yml -e router_user=netops -e up_timeout=600
```

**Aborting:** at any confirmation gate, `Ctrl-C` then `A` stops the whole run.

**Unattended** (`-e gate=auto`) skips the confirmation prompt. CI passes it, because a
`pause:` in a pipeline would hang until the job timed out. The default stays `manual`. You
have to ask for automation. The safe behaviour shouldn't depend on remembering to request it.

With `gate=auto` the gate doesn't disappear. It **moves**. In the pipeline the confirmation is
the functional gate running against the *previous* router, as a `needs:` edge. Router N+1's
job can't start until router N passed its functional tests. Stricter than the prompt ever was.
The prompt only asked whether you'd looked.

**Resuming** after an abort or a fix: limit to the routers not done yet, order preserved:

```bash
ansible-playbook deploy.yml --limit br2.ord2,er2.hdc
```

## Skipping unchanged devices (idempotence)

The goal is Terraform-style "leave it alone if nothing changed." A true declarative diff
against the *live* config isn't practical here. The apply is a destructive
`reset-configuration` replaying an `add`-only build script, and that script isn't comparable
to a live `/export` without a fragile normalization pass. So this borrows the idea behind
Terraform's **state** instead:

- After a **verified** deploy the playbook stores a fingerprint (sha256 of the applied
  `.rsc`) on the device as `<fqdn>.applied`. Files survive `reset-configuration`. Same reason
  `run-after-reset` works.
- Next run it regenerates the config, compares the hash to that fingerprint and **skips the
  device with no reboot if they match.** The generator is deterministic (same `topology.yml`
  → byte-identical `.rsc`) so a match means something.

What it **doesn't** catch:

- **Live drift.** Hand-edit the running router and the fingerprint still matches the last
  *applied* config, so it reports unchanged. It tracks "did the intended config change since
  we last pushed", not "does the box match".
- A device deployed **outside this tool** (say, by console) has no fingerprint. It gets
  reported changed and offered for redeploy.
- The fingerprint only updates **after the identity check passes**. A failed or half-applied
  deploy is *not* recorded and the next run still sees it as changed.

Overrides:

```bash
ansible-playbook deploy.yml -e force=true              # redeploy even if unchanged
ansible-playbook deploy.yml -e skip=er1.hdc,br2.ord2   # skip these routers entirely
ansible-playbook deploy.yml --limit br1.ord1           # or just run one/some
```

`skip` and `--limit` are both manual overrides. Use them when *you* know whether a device
changed. `skip` keeps the full inventory in the run and excludes the named hosts before any
reachability check. `--limit` narrows the run itself.

## Password auth fallback (if you don't use SSH keys)

The playbook assumes key auth (`BatchMode=yes`). For a password install `sshpass`, drop
`BatchMode=yes` from `ros_ssh_opts` in [`inventory.yml`](inventory.yml) and prefix the
`ssh`/`scp` calls with `sshpass -e` (export `SSHPASS` first). Use keys if you possibly can. A
password prompt mid-reboot is exactly where an unattended rollout hangs.

## What each step does

| Step | Purpose |
|---|---|
| Preflight | `.rsc` exists locally and the router answers SSH now (catches the mgmt-source-filter mistake early) |
| **Gate** | Manual confirmation. Last chance to check the previous box and abort |
| Upload | `scp` the config up and check it landed on the router's filesystem |
| Reset | `reset-configuration … run-after-reset=…`. The link drops (non-zero rc is expected) |
| Wait down | SSH must stop. Proof the reset happened and wasn't a silent no-op |
| Wait up | SSH must come back. Proof the script re-created SSH-on-mgmt |
| Verify | Read `/system/identity` back and assert it matches the router |
| **Reboot** | Second reboot so the IPv6 RA setting takes effect. Every applied router, see below |
| State | Stash the config fingerprint on the device for next run's change detection |

The identity check is a smoke test that the script ran. **Not** a full health check. That's
the functional gate's job. Run it after every deploy and let it gate the next one.

```bash
pytest tests/functional --router br1.ord1 --focus br1.ord1
```

## The second reboot (IPv6 Router Advertisements)

**Every router that gets config applied reboots twice.** Not belt and braces. Without the
second reboot the IPv6 RA setting never takes effect.

RouterOS doesn't apply `/ipv6/settings accept-router-advertisements` until a reboot. WinBox
shows a red banner saying so.

Why it hits *every* deploy:

1. `reset-configuration` wipes the config, restoring the RA setting to its
   factory default (`yes-if-forwarding-disabled`), and reboots.
2. `run-after-reset` applies our `.rsc`, which **sets** the RA value.
3. Nothing reboots after step 2, so the value we just set never takes effect.

Step 1's reboot doesn't count. It happens *before* our value is written.

**It applies to all four routers, not just the RA one.** The factory default is
`yes-if-forwarding-disabled`, so `br2` and both ERs setting `=no` change it just as much as
`br1` setting `=yes`:

| Router | `wan_v6.gateway` | Renders | vs factory default |
|---|---|---|---|
| `br1.ord1` (Vultr) | `ra` | `…=yes` | changed |
| `br2.ord2` (HostHatch) | `fe80::1` | `…=no` | changed |
| `er1.hdc` / `er2.hdc` | — (v4-only WANs) | `…=no` | changed |

So the reboot is **unconditional**. Any future setting that needs a reboot is already covered
without touching this logic. The cost is bounded. Unchanged devices end the play before this
point and are never touched. A device that gets here was being wiped and rebooted anyway.

**Why it can't live in a runbook:** it comes back on every reset-and-restore, the only way this
repo applies config. A manual step repeated on every deploy eventually gets skipped. And the
failure is silent. v4 comes up perfectly and nothing complains.

### The `::/0` assertion is narrower than the reboot

Afterwards, on `gateway: ra` routers **only**, the playbook asserts an active `::/0` route
exists. It retries for two minutes while the box sends its Router Solicitation and waits for
the reply.

Narrow on purpose. Who needs the reboot (everyone) is a different question:

- **br1**: the default exists *only if* the reboot worked. Real proof.
- **br2**: its default is a static route in the `.rsc`, there either way. It'd pass whether or
  not the reboot did anything.
- **er1/er2**: no v6 default of their own. Theirs arrives over iBGP once sessions come up.
  Asserting `::/0` here would fail them for reasons that have nothing to do with the reboot.

If the assertion fails, check on the router:

```routeros
/ipv6/settings print
/ipv6/route print where dst-address="::/0"
```

and confirm the upstream is actually sending RAs on `ether1`.

---

# RouterOS upgrades (`upgrade.yml`)

Separate playbook, same inventory, same order, same gates:

```bash
cd ansible

ansible-playbook upgrade.yml --check    # report every router's version — changes nothing
ansible-playbook upgrade.yml            # upgrade whatever is behind
```

**It doesn't touch the config.** No reset, no `run-after-reset`, no `.rsc` upload. The config,
the files on the router (including `deploy.yml`'s `<fqdn>.applied` fingerprint) and the licence
all survive a package upgrade. Deploy and upgrade are independent. Run them in either order.

Per router:

| Step | Purpose |
|---|---|
| Preflight | SSH answers; identity matches inventory; enough free space for the `.npk` |
| **Snapshot** | Record BGP established / OSPF Full / active routes / anchor routes **before** |
| Check | `check-for-updates`, read `installed-version` vs `latest-version` |
| Guard | Refuse a **major**-version jump unless `-e allow_major=true` |
| Skip | Already latest (and firmware current) → end host, **no reboot** |
| Backup | `/system/backup save` + `/export`, fetched to `out/backups/` |
| **Gate** | Manual confirmation, showing both versions and the health snapshot |
| Download | `/system/package/update download`. **Router stays in service** |
| Reboot | The version changes here. Wait down → up → assert the new version |
| Firmware | RouterBOARD only: `/system/routerboard upgrade` + a second reboot |
| **Health** | Retry until BGP + OSPF are back to the snapshot, then assert |

## Download and reboot are separate on purpose

`/system/package/update install` downloads *and* reboots in one shot, so a download that fails
or stalls has already cost you the router's uptime. Download first and a failed fetch leaves the
box **fully in service on its old version**. The assertion says so when it fires. The reboot only
happens once the `.npk` is on disk.

## The health check is relative, never absolute

Nothing is asserted against a hardcoded number. The playbook counts BGP sessions, `Full` OSPF
neighbours, active routes and blackhole (anchor) routes *before* the upgrade. Afterwards it
retries for five minutes until the box is **no worse off than it started**. Two reasons. The
numbers change as `topology.yml` grows. And a session that was already down beforehand shouldn't
get blamed on the upgrade.

Hard assertions. These stop the rollout:

- BGP established `>=` before
- OSPF `Full` neighbours `>=` before
- v4 and v6 blackhole/anchor routes `>=` before. Counted without caring about role, so it works
  on a BR's `/24` anchor and an ER's `/25` home-anchor without either prefix appearing in the
  playbook. Disabled anchors still count because `anchor-guard` disables them legitimately.

Warnings. Reported, not fatal:

- Active route count dropped more than 10% (upstreams churn on their own)
- BFD sessions. Additive under OSPF, so a missing session costs convergence speed, not
  connectivity. But `use-bfd=yes` with sessions that never come up is exactly what
  `topology.yml`'s two-pass rollout exists to avoid.

## The major-version guard

A minor upgrade goes ahead. A **major** one (7.x → 8.x) aborts the whole run on the first router
before anything's been touched.

Not caution for its own sake. The repo README already flags it under *"Things the generator
cannot check for you"*. The `ebgp-out` chains in `br.rsc.j2` are written against the **ROS7** rule
language and *matcher names drift between releases*. A box that comes back with quietly broken
routing filters looks perfectly healthy. SSH answers, BGP establishes, OSPF goes Full and every
assertion here passes. Nothing automated catches it.

So when it fires: read the release notes, upgrade **one** border router, run the anchor-guard
test from the repo README and confirm the filters still do what they claim. Then:

```bash
ansible-playbook upgrade.yml -e allow_major=true
```

## Channels

The channel is **left alone by default**. Switching channels is a decision, not a side effect of
asking for updates. The gate shows which channel each router is on. To switch:

```bash
ansible-playbook upgrade.yml -e channel=stable      # or long-term / testing
```

## Other overrides

```bash
ansible-playbook upgrade.yml -e upgrade_firmware=false   # RouterOS only, skip RouterBOOT
ansible-playbook upgrade.yml -e fetch_backups=false      # don't pull backups locally
ansible-playbook upgrade.yml -e skip=er1.hdc,br2.ord2    # leave named routers alone
ansible-playbook upgrade.yml --limit br1.ord1            # or run just one
ansible-playbook upgrade.yml -e converge_retries=40      # longer reconvergence budget
```

## Prerequisites beyond the deploy ones

- **The routers need DNS and outbound HTTPS to `upgrade.mikrotik.com`.** If `check-for-updates`
  can't resolve or connect the playbook fails at the check with nothing changed. The BRs reach it
  over their provider default and the ERs through the tunnels.
- **Free space.** The playbook asserts >25 MB before doing anything. Old backups, exports and
  `.npk` files from previous upgrades pile up in `/file`. That's what fills a small board.

## The fetched backups are secret material

`out/backups/<fqdn>-pre-<version>.backup` is a full binary backup and **holds the WireGuard
private keys**. The companion `.rsc` export is RouterOS's own `/export`, which masks secrets by
default and is handy to diff against `out/<fqdn>.rsc`. That's why `out/` is gitignored. Keep it
that way.

## What it still doesn't do

Same boundary as `deploy.yml`. The assertions are a smoke test that the box came back and
re-established what it had. **Not** proof the network is correct. Check the `/24` anchor, the
`/25` and the eBGP sessions with the firewalls yourself before releasing each gate.


---

# Pinned upgrades (`upgrade-npk.yml`)

`upgrade.yml` asks each router for "latest on its channel" and has it fetch the package itself.
This one's the other way round. **You name the version**, the control node downloads the `.npk`
from `download.mikrotik.com` and `scp` puts it in each router's root. Every router lands on the
same build and the routers need no DNS or HTTPS to MikroTik.

MikroTik has no "latest" link (downloads are keyed by version) so pass one of:

```bash
cd ansible

ansible-playbook upgrade-npk.yml -e ros_version=7.24.5 --check   # report only
ansible-playbook upgrade-npk.yml -e ros_version=7.24.5           # gate before each router
ansible-playbook upgrade-npk.yml -e npk_url=https://download.mikrotik.com/routeros/7.24.5/routeros-7.24.5.npk
```

With `ros_version` the file is picked per router from `/system/resource architecture-name`
(`routeros-<v>.npk` for x86_64 CHRs, `routeros-<v>-<arch>.npk` otherwise). With `npk_url` the
file has to match the router's architecture or the run stops before uploading. A wrong-arch
package gets quietly ignored and the router reboots on its old version.

Per router, same order and gating as the others (`-e gate=auto` to skip the prompt):

| Step | Purpose |
|---|---|
| Preflight | SSH answers, identity matches, only the `routeros` package installed, arch read |
| Package | HEAD the URL. Proves the version exists for this arch and gets its size |
| Decide | Already on it (or newer) → end host, **no reboot**. Major-version guard as in `upgrade.yml` |
| Root check | No other `.npk` in `/file` root. RouterOS installs **every** one there on reboot |
| Space | Free space > package + 10 MB |
| Download | To `out/npk/` on the control node, cached across routers. Size checked against the server |
| **Gate** | Shows versions, package and BGP/OSPF counts before |
| Upload | `scp` to the root. Byte count on the router must match |
| Reboot | Wait SSH down → up. Assert the installed version and identity |
| **Health** | Retry until BGP established + OSPF Full are back to the pre-reboot counts |

The next router isn't touched until the previous one is on the new version **and** reconverged,
so the BR/ER alternation actually holds.

MikroTik doesn't publish a checksum next to the `.npk`. The size checks catch a truncated
transfer. RouterOS checks the package signature itself before installing.

**Zabbix.** RouterOS resets SNMPv3 `engineBoots` on a package install and Zabbix drops every reply
from a router whose counter went backwards. All hosts go "Timeout while connecting" at once. So
both upgrade playbooks end by importing
[`zabbix-snmp-reload.yml`](zabbix-snmp-reload.yml), which runs
`zabbix_server -R snmp_cache_reload` on the Zabbix host (`zabbix_ssh_target` in
`group_vars/all.yml`) **only if a router actually rebooted onto a new package**. A failure there
is a warning, not a failed run. If an upgrade aborts halfway the reload never runs, so run
`ansible-playbook zabbix-snmp-reload.yml` by hand. `-e zabbix_snmp_reload=false` skips it.

**Extra packages** (container, wireless, …) stop the run at preflight. Only `routeros-<v>.npk`
gets pushed and an extra package left on the old version is refused at boot. Use `upgrade.yml`
for that router. No firmware step either. The fleet is CHRs.

---

# The functional gate

Read-only. It's what makes a deploy *successful* and not just *finished*. It lives in
`pytest tests/functional`, not here. [`docs/netdevops.md`](../docs/netdevops.md) has the full
list of checks and why nothing else covers each one.

`deploy.yml` proves a router came back with the right identity. A smoke test. A router whose
import was **rejected on line 700** passes it. RouterOS stops at the first line it can't parse
and skips everything after, so the box answers SSH, reports the right name and has no BGP at all.
The gate reads the log for exactly that. Then it checks WireGuard handshakes, OSPF per address
family, every iBGP and eBGP session by peer address, the customer routes, the anchors, both
defaults, the loopback mesh, the tunnel MTU in both directions and BFD.

```bash
pytest tests/functional --router br1.ord1 --focus br1.ord1
```

`--focus` adds the fleet cross-check. Every *other* router must still reach the one just
deployed. A router can pass every check about itself while a peer can't reach it. A mismatched
WireGuard listen port does exactly that and only the peer knows.

## Calibrate it before you trust it

```bash
pytest tests/functional -q
```

Run this against a fleet you already know is healthy. Once now, and again after any RouterOS
upgrade. The probes read RouterOS properties and property names drift between releases. The repo
README says so about the routing filters and it's just as true here.

A gate that fails for the wrong reason is a gate somebody disables, and then it gates nothing.
The probes are defensive about it. Each section is error-trapped on its own and reports
`PROBE-ERROR` instead of an empty list, so a renamed property reads as a tooling problem and not
a dead network. But defensive isn't verified.

**Not hypothetical.** The first calibration run against the live fleet found that
`find where ... blackhole=no` matches nothing in RouterOS (the property is *unset* on rows where
it doesn't apply, not set to `no`). And `anchor-guard` used exactly that spelling. It would have
withdrawn the `/24` ten minutes after anyone armed its scheduler.
See [AD-LOG §29.8](../AD-LOG.md).

---

# Failover, proved (`chaos.yml`)

[`docs/failure-modes.md`](../docs/failure-modes.md) describes what happens when an upstream, a
WAN or a firewall dies. Claims about **behaviour**. The functional gate only asserts **state**,
and a network can sit in a perfectly healthy state and still fail to converge when you take
something away.

Ansible breaks and restores. The assertion in the middle is the **same** pytest end-to-end test
the pipeline gates on. A failover test that checks something weaker than the real test proves
something weaker than the real test.

```bash
ansible-playbook chaos.yml                      # all three
ansible-playbook chaos.yml -e scenario=upstream # one BR loses transit
ansible-playbook chaos.yml -e scenario=wan      # one ER loses wan1
ansible-playbook chaos.yml -e scenario=customer # one firewall session drops
```

Each scenario baselines the path, breaks one thing, asserts the **same** end-to-end test still
passes and restores.

## The deadman

Every scenario schedules its own undo **on the router** before breaking anything and cancels it
after restoring. Playbook killed, control node lost power, partition took out the control node
along with the path under test? The router repairs itself in 10 minutes with nobody around.

An `always:` block isn't enough. `always:` runs when a *task* fails, not when the *process* dies.
And a test whose whole job is severing a network path is unusually likely to sever the path the
restore would have used.

```routeros
/system/scheduler print where name=chaos-deadman
```

Find one of those on a router? A chaos run died. Harmless, it re-enables things that should be
enabled. But remove it and check what happened.

## Why it is manual, always

It breaks a live path. Run it when you're watching, not while you're reviewing somebody else's
commit. In the pipeline it's a `when: manual` job and no configuration makes it automatic.
