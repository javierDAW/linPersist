# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Repository skeleton: layout, Makefile, Apache-2.0 LICENSE, .gitignore.
- `matrix.yaml` source of truth for MITRE ATT&CK coverage (15 site_classes
  planned for v0.1.0).
- `internal/core` skeleton: `Module` interface, `Record` struct with NDJSON
  tags, runner stub with per-module timeout, NDJSON emitter, hashing and
  normalization helpers, host metadata collector stub, signal helpers,
  provenance stub.
- `cmd/linpersist/main.go` CLI entry point with `--output`,
  `--include-hostname`, `--module-timeout`, and `--version` flags.
- `tools/verify_static.sh` portability gate (`ldd` + `file` checks).
- `docs/schema-v1.md` canonical NDJSON record description.
- `docs/adr/0001-module-interface.md` ADR for the `Module` interface.
