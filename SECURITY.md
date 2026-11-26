# Security Policy

This repository publishes the signed Citadel threat pack (`threat-pack.json`) and the
tool that signs it.

## Reporting a vulnerability

Please report problems privately, not in a public issue: use the **Security** tab →
**Report a vulnerability** on this repository.

Of particular interest:

- Anything that lets a pack be accepted without a valid signature chain
  (`delegation.json` signed by the offline update key, then the pack signed by the pack key).
- Any way to get the workflow to run code other than the pinned tool binaries in `tool/`.
- Entries in the pack that would block legitimate traffic.

## Notes

- The offline update key never leaves its owner. Only the online pack key is a repository secret.
- The binaries in `tool/` are checked against pinned SHA-256 hashes in
  `.github/workflows/daily.yml` before they run. Update the hashes in the same commit
  as any deliberate rebuild.
