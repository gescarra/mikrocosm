# Changelog

Notable changes go here. Format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- First public release. A topology-driven RouterOS v7 config generator for a dual-stack
  two-BR / two-ER autonomous system. WireGuard mesh, OSPFv2/v3 + BFD, full-mesh iBGP and eBGP
  customers with generated UniFi FRR configs. External peering realms (internet, bilateral
  VRF, DN42), RPKI, traffic engineering, RTBH, SNMPv3, remote sites and AWS BYOIP tooling.
  Ansible rollout, GitLab pipeline and unit and functional test suites.
- `demo.sh` to render the example topology offline.
- GitHub Actions workflow running the unit suite and the offline render.
