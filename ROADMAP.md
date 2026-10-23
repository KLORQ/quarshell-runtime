# Roadmap — quarshell-runtime

Status: pre-stable API · Current module tag: `v0.1.1` · Dependencies are listed in `go.mod`.

## This module

| ID | Item | Notes |
|----|------|-------|
| T1 | **Image catalog** | Keep GHCR `sandboxes/{base,gui,gpu,gui-gpu}` in sync with tags; GPU GUI remains experimental |
| T2 | **Secrets store** | Map/Env → Vault adapters |
| T3 | **Identity federation** | Align gateway OIDC/mTLS and workload identity with OpenShell config and authorization semantics |
| T4 | **Harden depth** | Landlock/seccomp profile documentation |


## Release

This module follows its own pre-stable 0.x version sequence. Publish dependencies
first, update consumers to the published tags, and verify with `GOWORK=off`. Never
rewrite a published tag.
