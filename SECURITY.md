# Security policy

## Reporting a vulnerability

Report security issues privately through GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository. Not in a
public issue or PR.

Include what you found, how to reproduce it and the impact as you see it. Expect an
acknowledgement within a week. Fixes ship when they're ready and you get credited in the
advisory unless you'd rather not.

## What counts

This renders router config, so the interesting bugs are usually in what it generates. Less so
in the Python. In scope, for example:

- A topology that renders a config which leaks routes, becomes transit or accepts prefixes
  outside a customer's or peer's grant.
- Firewall or input-chain output that exposes management, SNMP or BGP to sources the topology
  didn't allow.
- Secrets (WireGuard private keys, PSKs, MD5 keys, SNMP passphrases) reaching an artifact
  that's meant to be safe to share: `manifest.json`, `inventory.yml`, `pipeline.yml`, customer
  `.conf` files, CI logs or stdout.
- Validation that accepts an input it claims to refuse.

Out of scope: bugs in RouterOS itself (report those to MikroTik) and anything that needs an
attacker who can already edit `topology.yml` or read `keys.json`.

## Handling secrets as a user

- `keys.json` and `out/` hold private keys. They're gitignored. Keep it that way.
- `topology.yml` is meant to be committed. The one exception to "no secrets in topology.yml"
  is the upstream `bgp_auth_key` values, so treat a repo holding real ones as private.
- Key exposed? Rotate it with `./build.sh --rotate-keys` and redeploy.
