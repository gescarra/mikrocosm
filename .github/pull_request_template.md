## What and why

<!-- What changes and what failure or need is behind it? -->

## Checklist

- [ ] `pytest` passes
- [ ] `./demo.sh` renders the example topology
- [ ] New schema is validated in `generate.py` with an actionable error
- [ ] Docs / `topology.yml` comments updated; `AD-LOG.md` entry if this is a design decision
- [ ] Only documentation ranges (AS64496-64511, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, example.net) in examples and tests
- [ ] No secrets, `keys.json` content or rendered `.rsc` in the diff

## Tested on

<!-- RouterOS version and hardware/CHR, or "not tested on hardware". -->
