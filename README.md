# Duo Audit

![Duo Audit](image.png)

Audit Duo Security configurations against **FedRAMP Consolidated Rules for 2026** Key Security Indicators (**KSI-IAM**), using the official indicator set from [FedRAMP/2026-markdown](https://github.com/FedRAMP/2026-markdown), plus **NIST SP 800-63B** and **CISA** phishing-resistant MFA expectations.

Author: [Ethan Troy](https://ethantroy.dev)

## Features

- Maps Duo Admin API signals to the **six official KSI-IAM** indicators from the 2026 markdown corpus:
  - `KSI-IAM-AAM` — Automating Account Management  
  - `KSI-IAM-APM` — Adopting Passwordless Methods (includes phishing-resistant MFA when passwordless is not feasible)  
  - `KSI-IAM-ELP` — Ensuring Least Privilege  
  - `KSI-IAM-JIT` — Authorizing Just-in-Time  
  - `KSI-IAM-SNU` — Securing Non-User Authentication  
  - `KSI-IAM-SUS` — Responding to Suspicious Activity  
- Emits **machine-readable evidence** (`fedramp_20x_ksi_evidence.json`) suitable for scheduled regeneration
- Human-readable FedRAMP / NIST / CISA reports and executive summary
- Explicit about **limits**: Duo cannot fully prove JIT or automated SUS response; those stay `unknown` pending IdP/process evidence

## Requirements

- Python 3.8+ (3.10+ recommended)
- `pip install -r requirements.txt` (`duo_client`, `colorama`, `tabulate`)

## Installation

```bash
git clone https://github.com/ethanolivertroy/Duo-Audit.git
cd Duo-Audit
pip install -r requirements.txt
```

## Usage

```bash
./duo-audit.py
./duo-audit.py --host api-xxxxx.duosecurity.com --ikey YOUR_INTEGRATION_KEY --skey YOUR_SECRET_KEY
./duo-audit.py --output-dir /path/to/output
```

| Artifact | Purpose |
|----------|---------|
| `fedramp_compliance_report.txt` | Narrative assessment against official KSI-IAM IDs |
| `fedramp_20x_ksi_evidence.json` | Machine-readable KSI status + evidence fields |
| `executive_summary.txt` | Leadership rollup |
| `compliance_checklist.txt` | Manual verification (2026 KSI-IAM + legacy Rev5 themes) |
| `security_decision_records/` | Per-KSI **Security Decision Record** markdown stubs |

JSON includes **`ruleset_provenance`** with a pinned `FedRAMP/2026-markdown` **commit SHA** (refresh `FEDRAMP_2026_MARKDOWN_PIN` in `duo-audit.py` when the corpus moves).

**KSI-IAM-SUS:** administrator logs contribute *weak* signals (e.g. disable-like actions) but never auto-`pass` — response automation must be attested in the SDR.

## FedRAMP source of truth

Use the **Consolidated Rules for 2026** markdown corpus—not Phase One pilot / RFC-0006 alone:

- Repository: <https://github.com/FedRAMP/2026-markdown>
- IAM KSIs: [`providers/20x/key-security-indicators/identity-and-access-management.md`](https://github.com/FedRAMP/2026-markdown/blob/main/providers/20x/key-security-indicators/identity-and-access-management.md)
- KSI overview: [`providers/20x/key-security-indicators/index.md`](https://github.com/FedRAMP/2026-markdown/blob/main/providers/20x/key-security-indicators/index.md)
- Full KSI reference dump: [`reference/key-security-indicators.md`](https://github.com/FedRAMP/2026-markdown/blob/main/reference/key-security-indicators.md)

That content is generated from FedRAMP machine-readable rules (see the repo README). Indicator launch notes in that corpus include **2026-06-24** for Consolidated Rules for 2026.

## Security Notice

This tool retrieves sensitive configuration data. Control access to outputs, redact secrets before sharing, and follow your organization’s handling policies.

## FIPS & Trusted Endpoints

Often **not** fully exposed via the Duo Admin API client. Verify Duo Federal / FIPS components manually ([Duo Federal Guide](https://duo.com/docs/duo-federal-guide)).

## License

**[Unlicense](https://unlicense.org)** — see [`LICENSE`](LICENSE). Ethan Troy — <https://ethantroy.dev>
