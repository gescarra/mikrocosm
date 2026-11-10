# Contributing

This generates config for routers that carry real traffic. The bar is "provably correct" and
not "looks right". Good news: most of the proving is automated.

Grab a coffee. The comments in this repo are long on purpose and most of them exist because
something broke once.

## Ground rules

- **Never commit secrets.** `keys.json`, `out/`, `.env` and `aws/*.pem` are gitignored for a
  reason. `tests/unit/test_secrets.py` fails the build if anything key-shaped reaches an artifact.
- **Use documentation ranges in examples and tests**: AS64496-64511, `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20` and `example.net` /
  `example.org`. Please don't put your own network's numbers in a PR.
- **Derive, don't declare.** If a value can be computed from something already in
  `topology.yml` then compute it in `generate.py`. The generator refuses declared values it
  could have derived. New schema follows the same rule.
- **Validate before rendering.** Deploys run after `reset-configuration`, so a config RouterOS
  rejects halfway through an import is worse than no config. New options need a check in
  `validate()` that fails at build time and says how to fix it.
- Be kind. See the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest          # the unit suite, about a minute
./demo.sh                 # render the example topology into out/
```

CI runs Python 3.12. `wg` (wireguard-tools) is optional. There's a pure-Python fallback for
key generation.

## Making a change

1. **Open an issue first** for anything bigger than a bug fix. Let's agree on the shape before
   you write it.
2. **Write the test first** where you can. `tests/conftest.py` gives you a `topology` fixture
   and a `render` helper that runs the real generator hermetically. Most tests take the example
   topology, change one thing and assert on the rendered `.rsc` or the refusal.
3. **Keep the example rendering.** `./demo.sh` must succeed on `topology.yml` as committed.
4. **Explain the why.** Comments here record the failure a line exists to prevent. If it's a
   design decision, add an `AD-LOG.md` section: what was chosen, over what and why.
5. **Test on hardware when you touch RouterOS syntax.** Properties move between releases. Say
   in the PR which version you tested on, or that you couldn't.

## Pull requests

- One logical change per PR. Say what changed and why.
- `pytest` passes and `./demo.sh` renders.
- Changing a template? A before/after diff of a rendered `.rsc` is the most useful thing you
  can paste.
- Update the docs if behaviour or schema changed. The `topology.yml` comments are the schema
  docs.

## Reporting bugs

Use the bug report template. Include the RouterOS version, the relevant bit of your
`topology.yml` with documentation ranges in place of your numbers, the command you ran and the
full output. **Never paste `keys.json` or a rendered `.rsc`.** Both hold private keys.

## Security issues

Please don't open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
