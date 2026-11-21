# Citadel threat pack

`threat-pack.json` is the signed file every Citadel PC fetches (about every 6 hours) from
`https://raw.githubusercontent.com/MatRIXTEaM-code/Citadel-ThreatPack/main/threat-pack.json`.

It can only **add alerts**: extra brand names for the look-alike check, known-bad domains and addresses, and extra command rules.
It never blocks, deletes or runs anything on a PC. It expires after 14 days, so a stalled publisher cannot leave stale entries in force.

## How it stays fresh (no human step)

`.github/workflows/daily.yml` runs every Monday (05:17 UTC):
1. `research/research.py` asks Claude (with web search) for new indicators from public reports in the last 7 days.
2. `tool/PackTool.dll --merge-pack` checks every entry on its own: well-known sites can never be flagged, private and reserved
   addresses and ranges wider than /24 are refused, command rules that match an everyday command are refused, additions per run are capped,
   and domains and addresses age out after 30 days (rules after 90).
3. The result is signed with a **pack-only key**. `delegation.json` is a certificate, signed by the offline update key, that lets this key sign
   threat packs and nothing else, until its expiry date. PCs verify the whole chain.
4. The new `threat-pack.json` is committed.

## Secrets (repository settings > Secrets and variables > Actions)

- `PACK_KEY_JSON`: the full contents of `pack-key.json`.
- `ANTHROPIC_API_KEY`: an Anthropic API key (any workspace key; the job makes a few web-search requests a day).

## Emergency stop

Run the workflow with an empty `research/proposal.json` and delete the old entries, or publish a pack with a higher serial and nothing in it.
To revoke the pack key entirely, stop renewing `delegation.json`: PCs ignore packs once it expires. Renew it (about once a year) by signing a new one on the
offline machine: `PackTool --sign-delegation --key update-key.json --pack-key pack-key.json --days 365 --out delegation.json`.
