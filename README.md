# Bifrost Critical: Stored XSS via Backend Database → Click-to-Drain Wallet

**Severity**: Critical
**Target**: https://app.bifrost.io (Immunefi in-scope)
**Authentication**: NONE required

## Summary

Zero-authentication stored XSS attack chain that enables one-click wallet
drain of any user who views a poisoned governance proposal on app.bifrost.io.

```
Grafana anonymous API → SQL superuser → dblink → Hasura metadata
→ 10 DB credentials → write to polkassembly_post → inject javascript:
markdown link → remark renders (no sanitization, no CSP) → user clicks
→ drain script loads → wallet APIs → FUNDS DRAINED
```

## Files

| File | Description |
|------|-------------|
| `REPORT.md` | Full Immunefi submission — bug description, impact, CVE references, 8-phase PoC walkthrough, theoretical drain payload, remediation |
| `scripts/poc-xss-chain.sh` | Automated read-only PoC — 37 checks proving every link in the chain |

## Run the PoC

```bash
chmod +x scripts/poc-xss-chain.sh
./scripts/poc-xss-chain.sh
```

**Requirements**: `curl`, `python3`, internet access. No credentials needed.

**The script is 100% read-only. No data is modified. No XSS is injected.**

## Key Findings

- **Entry**: `stats.bifrost.io` Grafana anonymous API → PostgreSQL superuser (cf. **CVE-2024-9264**)
- **Lateral movement**: `dblink` → Hasura metadata → all 10 data source credentials
- **Write access**: `monitor.polkassembly_post` — 2,484 governance proposals, superuser INSERT/UPDATE/DELETE
- **Data flow**: DB → Hasura GraphQL → `dapi.bifrost.io` → `app.bifrost.io` (markdown `content` field)
- **No defenses**: No CSP, no DOMPurify, no rehype-sanitize, no sanitize-html
- **Wallet APIs**: `window.ethereum`, `WalletConnect`, `polkadot-js` / `injectedWeb3` all in same origin
- **XSS vector**: `javascript:` protocol markdown link rendered by `remark` → click-to-drain (cf. **CVE-2025-24981**, **GHSA-m7qm-r2r5-f77q**)

## Related CVEs

| CVE | CVSS | Relevance |
|-----|------|-----------|
| **CVE-2024-9264** | 9.9 | Grafana SQL via `/api/ds/query` — same entry point |
| **CVE-2025-24981** | 9.3 | Markdown XSS via `javascript:` URL — exact same vector |
| **CVE-2024-21535** | 5.3 | `markdown-to-jsx` XSS via `javascript:` protocol |
| **GHSA-m7qm-r2r5-f77q** | — | `react-marked-markdown` XSS — identical payload pattern |
| **CVE-2025-3454** | — | Grafana datasource proxy authorization bypass |

## Disclaimer

All findings are read-only proofs. No XSS payloads were injected. No data was
modified. No wallets were drained. This report is submitted in good faith under
Bifrost's Immunefi bug bounty program.
