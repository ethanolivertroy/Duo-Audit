# Duo Audit

![Duo Audit](image.png)

Audit Duo Security configurations against **FedRAMP 20x Key Security Indicators (KSIs)** (IAM themes), legacy FedRAMP / NIST SP 800-53 Rev 5 control themes, **NIST SP 800-63B**, and **CISA** phishing-resistant MFA expectations—using the official Duo Admin API client.

Author: [Ethan Troy](https://ethantroy.dev)

## Features

- Maps Duo Admin API signals to **FedRAMP 20x KSI-IAM** outcomes (phishing-resistant MFA, authenticator strength, least privilege, account automation readiness, integrations, session monitoring)
- Emits **machine-readable evidence** (`fedramp_20x_ksi_evidence.json`) for continuous / scheduled validation
- Still produces human-readable FedRAMP, NIST, and CISA reports plus an executive summary
- Actionable remediation guidance and a hybrid 20x + Rev5 checklist

## Requirements

- Python 3.8+ (3.10+ recommended)
- Dependencies (`pip install -r requirements.txt`):
  - `duo_client` — official Duo Security API client
  - `colorama` — colored terminal output
  - `tabulate` — formatted tables in reports

## Installation

```bash
git clone https://github.com/ethanolivertroy/Duo-Audit.git
cd Duo-Audit
pip install -r requirements.txt
```

## Usage

```bash
# Interactive prompts
./duo-audit.py

# Credentials on the command line
./duo-audit.py --host api-xxxxx.duosecurity.com --ikey YOUR_INTEGRATION_KEY --skey YOUR_SECRET_KEY

# Custom output directory
./duo-audit.py --output-dir /path/to/output
```

Reports land under `compliance_reports/`, including:

| Artifact | Purpose |
|----------|---------|
| `fedramp_compliance_report.txt` | FedRAMP 20x KSI narrative + legacy themes |
| `fedramp_20x_ksi_evidence.json` | Machine-readable KSI status + evidence fields |
| `executive_summary.txt` | Leadership-oriented rollup |
| `compliance_checklist.txt` | Manual verification checklist (20x + Rev5) |
| NIST / CISA / user / policy reports | Supporting assessments |

Re-run on a schedule and retain JSON artifacts to support FedRAMP 20x–style **persistent** validation.

## Security Notice

**Important:** This tool retrieves and stores sensitive security configuration data. Ensure you:

- Store output in a controlled location with appropriate access controls
- Redact secrets before sharing reports
- Use encrypted storage for archives
- Follow your organization’s data-handling policies

## Note on FIPS & Trusted Endpoints

FIPS status and trusted endpoints are **not** fully exposed via the Duo Admin API Python client in many tenants. The tool records what it can and flags **manual verification** for Duo Federal / FIPS-validated components (e.g. Authentication Proxy). See the [Duo Federal Guide](https://duo.com/docs/duo-federal-guide).

| Feature | API available? | How to check |
|---------|----------------|--------------|
| FIPS compliance | Often no | Duo Federal docs / console |
| Trusted endpoints | Often no | Admin Console |
| Users, admins, policies, logs | Yes | Admin API |

## Compliance frameworks assessed

- **FedRAMP 20x** — Key Security Indicators (especially **KSI-IAM** themes); see [RFC-0006](https://www.fedramp.gov/rfcs/0006/) and [IAM KSIs (preview)](https://preview.fedramp.gov/2026/providers/20x/key-security-indicators/identity-and-access-management/)
- **Legacy FedRAMP / SP 800-53 Rev 5 themes** — AC/IA-oriented checklist items for hybrid programs
- **NIST SP 800-63B** — authenticator assurance level signals
- **CISA ED 22-02** — phishing-resistant MFA expectations

This tool supports **evidence collection and heuristics**; it does **not** grant or revoke an ATO.

## License

Released under the **[Unlicense](https://unlicense.org)** (public domain dedication). See [`LICENSE`](LICENSE).

Copyright dedication: Ethan Troy — <https://ethantroy.dev>
