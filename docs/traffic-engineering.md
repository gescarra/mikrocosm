# Layer 4 — Traffic engineering

Multihoming gives you two ways out and two ways in. This is about **choosing between them**. Those
are two separate choices with two separate mechanisms:

| Direction | Who decides | Mechanism | Where it's configured |
|---|---|---|---|
| **Egress**: packets leaving AS64500 | **us** | `local-pref` on the default route | the ER/site, on *input* from each BR |
| **Ingress**: packets entering AS64500 | **the rest of the internet** | AS_PATH prepending on the aggregate | the BR, on *output* to its upstream |

Neither is on by default. With no `te:` block anywhere both BRs announce identically and the ERs hold
two identical defaults. Plain ECMP multihoming. The right starting point, and still the right answer
whenever both upstreams are equivalent.

## The asymmetry is real and it isn't a bug

You control egress completely. The default arrives from both BRs and you pick one. Nothing outside
the AS gets a say.

You don't control ingress at all. Every network in the DFZ picks its own path to `203.0.113.0/24`
with *its* policy. In almost every network local-pref ("prefer my customer over my peer over my
transit") is evaluated **before** AS_PATH length ever comes up. So a network whose commercial policy
prefers HostHatch sends you traffic through HostHatch however many times you prepend.

**Prepending is a hint.** It moves the networks that had no strong preference. In practice that's a
useful fraction and never all of it. A partial shift isn't a broken config. And don't crank the
prepend count chasing the rest. Past about five prepends you're adding path length nobody is still
deciding on.

## Egress: `te.local_pref`

```yaml
border_routers:
  - name: br1
    te: { local_pref: 200 }    # preferred
  - name: br2
    te: { local_pref: 100 }    # RouterOS's own default, stated explicitly
```

Each BR sends every ER and every site exactly one thing over iBGP: `0.0.0.0/0` (and `::/0`) via
`output.default-originate=if-installed`, gated by `default-guard`. Every BR's copy is otherwise
**identical**. Same empty AS_PATH, same origin, same MED. Without touching an IGP cost the only
attribute left to separate them is local-pref, the first tie-break in best-path selection.

The **receiver** applies the value **on input**:

```
add chain=ibgp-in-lp200 rule="if (dst==0.0.0.0/0 && dst-len==0) { set bgp-local-pref 200; accept }"
add chain=ibgp-in-lp200 rule="accept"
```

and the connection to that BR points at that chain. One chain per distinct value, not per peer. Two
BRs at the same local-pref share one, the same way `ibgp_out_class` avoids a second copy of an
identical output chain.

**Why the receiver and not the BR's `ibgp-out`.** Setting it at the sender would be a smaller diff
and it's the textbook spot. But the default route is *generated* by `output.default-originate`.
Whether RouterOS runs a generated route through the output filter chain isn't something you want to
discover on a live network. Same class of silent no-op as `network-blackhole=yes` quietly disarming
`anchor-guard`. An inbound UPDATE definitely goes through `input.filter`. The mechanism that can't
silently do nothing wins.

**Why it matches the default instead of being bare.** A BR carries nothing else into iBGP today. Its
`ibgp-out` rejects the `/24` and it re-advertises nothing it learned over iBGP. Scoping the rule to
`0.0.0.0/0` anyway means this knob can't quietly reweight whatever a BR starts carrying next.

**The BRs don't apply this to each other. On purpose.** A BR must never prefer a sibling's default.
It would egress through the sibling's transit and get its own-sourced packets dropped at that
provider's BCP38 filter. `provider_default_distance: 30` exists to prevent exactly that, and
`br.rsc.j2` keeps its plain `ibgp-in` for the same reason.

### Failover is unchanged

Local-pref is a preference, not a pin. When br1's eBGP session drops `default-guard` sets
`output.default-originate=never` on its downstream sessions. br1's default is withdrawn and the only
default left is br2's at local-pref 100. Best path, because it's the only path. When br1 comes back
the preference comes back with it. No failover logic anywhere. Same property the rest of the network
is built on.

## Ingress: `te.prepend`

```yaml
border_routers:
  - name: br1
    te: { prepend: 0 }         # preferred way in
  - name: br2
    te: { prepend: 5 }         # backup
```

renders, on br2 only:

```
add chain=ebgp-out-upstream rule="if (dst==203.0.113.0/24 && dst-len==24) { set bgp-path-prepend 5 }"
```

so the DFZ sees `... 65473 64500 64500 64500 64500 64500` via HostHatch against `... 64515 64500` via
Vultr. Any network still deciding on path length picks Vultr.

Three details you can't skip:

**Scoped to the aggregate, not the head of the chain.** A bare `set` at the top of
`ebgp-out-upstream` would prepend RTBH `/32`s too. A blackhole request wants the *shortest* path to
the upstream. `65535:666` is what stops the traffic, not distance. So the prepend matches the
aggregate and nothing else.

**Placed before the `64500:2:N` community ladder.** `set bgp-path-prepend` assigns. It doesn't
accumulate. The last rule to run is the one that ships, so the static value goes first and the
runtime community override (see [communities-rtbh.md](communities-rtbh.md)) can still out-vote
`topology.yml` on one prefix without a regenerate and redeploy.

**Both families, matched on what's actually announced.** The v6 twin matches `aggregate_v6`
(`2001:DB8::/42`), *not* `prefix_v6` (`2001:DB8::/40`). The allocation is never advertised. Both
families must carry the same policy or ingress moves on v4 and stays put on v6. The hardest kind of
TE change to notice.

## The four modes

The two keys are independent so you get all four without a mode enum:

| Want | `te.prepend` | `te.local_pref` |
|---|---|---|
| ECMP multihoming, no manipulation | omit | omit |
| Prefer a BR for **ingress** only | set on every BR | omit |
| Prefer a BR for **egress** only | omit | set on every BR |
| Prefer a BR for **both** | set on every BR | set on every BR |

**All or nothing.** Whichever key you use, `generate.py` refuses to render unless *every* BR sets
it, losing value included. `te: { local_pref: 200 }` on br1 with no `te` on br2 does work. But only
by pairing your number against a RouterOS default of 100 that appears nowhere in `topology.yml`.
Writing the 100 down costs one line and makes the comparison readable where you change it. And a
third BR added later fails the build instead of quietly inheriting defaults.

## Nothing forces the two axes to agree

In via br1 and out via br2 is **supported**. Not a mistake, and the generator won't warn about it.
Asymmetric routing breaks when a stateful device sees only one direction of a flow. No such device
sits on the split path here. Transit on the BRs is `notrack`'d so no BR holds state a return path
could miss. The customer firewalls at home stay on-path in *both* directions whichever BR carries
which half. Both upstreams accept `203.0.113.0/24` as a source address because we announce it to
them.

There are real reasons to want the split, like an upstream with better eyeball reach than transit
pricing or the reverse. So the model allows it.

## This doesn't put WAN preference in BGP

> "WAN preference is expressed **only** as OSPF cost, never in BGP."

Still true. That rule is about **which WAN** (`wan1` vs `wan2`) an ER uses to reach a router, and
that's still `ospf_cost` and nothing else. Traffic engineering is about **which border router /
which upstream** the AS prefers. Orthogonal. They compose without interacting:

- Prefer br1 for egress → traffic leaves the ER over `tun-wan1` (OSPF cost 10) toward br1's loopback.
  OSPF picked the WAN and BGP picked the BR.
- wan1 dies → OSPF reroutes to br1's loopback over `tun-wan2` (cost 100). The BR preference is
  untouched. Only the WAN moved.
- br1 dies → BGP moves to br2. The WAN preference is untouched. Only the BR moved.

An ER's `set bgp-local-pref` picks a *border router*. If you ever want to express `wan1` vs `wan2`
in a BGP attribute, that's the rule telling you to change a cost instead.

## ECMP is a separate switch

`bgp_multipath` (top level, default `false`) makes "no preference" mean load sharing instead of an
arbitrary tie-break. Without it an ER holding two identical defaults installs **one**. The IGP metric
can't separate them either since both BR loopbacks sit behind the same `tun-wan1` interface. RouterOS
breaks the tie on router-id. You're multihomed and every packet leaves through the same BR, picked by
an accident of addressing.

It applies on the BRs too, where the equal-cost pair is the home `/25` arriving from er1 *and* er2.
With multipath, inbound traffic to home is shared across both ERs instead of parked on whichever won
the tie-break. It's also what finally makes two firewalls claiming the same VIP at equal `local_pref`
really ECMP, which the `firewalls` section always claimed.

Setting `te.local_pref` makes the paths unequal so multipath collapses to the preferred BR on its
own. The two don't fight. ECMP is just what you get when you haven't expressed a preference.

### It's a count, and getting that wrong wipes the BGP config

`/routing/bgp/instance multipath` is typed `num`: "install the specified number of ECMP routes". Set
it to **2** for two BRs. Not `true`. `generate.py` refuses `true` by name instead of helpfully
rendering `yes`. `yes` is a type error the router rejects, and on this deploy path a rejected line
isn't harmless. `deploy.yml` runs `reset-configuration ... run-after-reset=<fqdn>.rsc` so the import
fails on that line **after** the box was wiped. Every `/routing/bgp` object below it (instance,
templates, connections, filter chains) never gets created. The router comes back reachable,
apparently healthy and running no BGP at all.

The property has moved around across RouterOS versions. **Verify it on a live box before enabling
it.** One line, reversible, doesn't disturb the session:

```
/routing/bgp/instance set [find name=core] multipath=2
/routing/bgp/instance print detail where name=core
/routing/bgp/instance set [find name=core] !multipath
```

`set` refused? Leave `bgp_multipath: false`. "No preference" then means a stable router-id
tie-break instead of load sharing, which is what this network did its whole life before the knob
existed. `te.local_pref` still works exactly as above because it makes the paths unequal and
multipath was never part of that.

The general rule this taught: a RouterOS property not already in these templates is unproven until a
live box accepts it, and the deploy path gives you no dry run. Default new ones OFF.

## Verifying

On an ER after a deploy:

```
/routing/route print detail where dst-address=0.0.0.0/0
```

- **Egress TE on**: the br1-nexthop route active with local-pref 200. br2's present and inactive.
- **Egress TE off, `bgp_multipath: 2`**: both active.
- Repeat for `::/0`. Both families must agree. If they don't, one of the `ibgp6-in-lp*` chains or
  connections is wrong.

On a BR, `/routing/route print detail where dst-address=203.0.113.0/25` should list **both** ER
next-hops once multipath is on.

From outside, a few minutes after convergence, any public looking glass or RIPE RIS: the path via
HostHatch carries the extra `64500`s and the path via Vultr doesn't. Expect a partial ingress shift
for the reason at the top of this doc.

To test failover without waiting for one: `/routing/bgp/connection disable ebgp-upstream` on br1. The
ERs should move the default to br2 within seconds and the DFZ should converge on the prepended but
now only path. Re-enable and confirm it shifts back.
