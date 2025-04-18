# Duo Audit

![Duo Audit](image.png)

A comprehensive tool for auditing Duo Security configurations against FedRAMP, NIST, and CISA compliance requirements. Using the official Duo Security API client for reliable and accurate compliance assessment.

## Features

- Evaluates compliance with FedRAMP security controls
- Checks adherence to NIST SP 800-63B authentication standards
- Validates conformance with CISA Emergency Directive 22-02 for phishing-resistant MFA
- Generates detailed compliance reports with findings and recommendations
- Provides actionable remediation steps for identified issues

## Requirements

- Python 3.6+
- Required Python libraries (install using `pip install -r requirements.txt`):
  - duo_client: Official Duo Security API client
  - colorama: For colored terminal output
  - tabulate: For formatted tables in reports

## Installation

1. Clone this repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic usage with prompts
./duo-audit.py

# Or specify credentials via command line
./duo-audit.py --host api-xxxxx.duosecurity.com --ikey YOUR_INTEGRATION_KEY --skey YOUR_SECRET_KEY

# Specify custom output directory
./duo-audit.py --output-dir /path/to/output
```

## Duo FIPS Status: API Endpoint Availability

**Summary:**
Duo Security does not provide an Admin API endpoint to programmatically check your deployment’s FIPS compliance. Attempts to call methods like `get_fips_status` will fail with:
```
FAILED: 'Admin' object has no attribute 'get_fips_status'
```

---

### Details
- **No FIPS Status Endpoint:** The official [Duo Admin API documentation][1] does not list any FIPS status endpoint. Available endpoints cover user, admin, device, log, policy, and integration management.
- **Script Error Explained:** The script error indicates attempting to call a non‑existent method (`get_fips_status`) in the Duo API Python client or underlying API.
- **FIPS Compliance in Duo:** FIPS compliance is managed via:
  - Use of Duo Federal editions
  - OS‑level FIPS mode for Duo components (Authentication Proxy, Unix integration, etc.)
  - Supported versions and configurations

---

### What You Can Do
- **Manual Verification:** Review your Duo deployment settings and edition (Federal vs. Commercial), and verify OS FIPS mode as described in the [Duo Federal Guide][2].
- **Administrative Console:** Check FIPS configuration and module validation under your Federal subscription settings.
- **Script Adjustment:** Remove or comment out calls to `get_fips_status` and `get_trusted_endpoints_config` in your custom scripts.

---

### Table: Duo API vs. FIPS/Trusted Endpoints
| Feature                   | API Endpoint Available? | How to Check                         |
|---------------------------|-------------------------|--------------------------------------|
| FIPS Compliance           | No                      | Manual/documentation review          |
| Trusted Endpoints Config  | No                      | Admin Console, documentation         |
| User/Admin/Policy Retrieval | Yes                   | Admin API                            |

---

[1]: https://duo.com/docs/adminapi
[2]: https://duo.com/docs/duo-federal-guide

You will be prompted for your Duo Admin API credentials if not provided as arguments.

## Compliance Standards Assessed

- **FedRAMP**: Federal Risk and Authorization Management Program requirements
- **NIST SP 800-63B**: Digital Identity Guidelines for authentication and lifecycle management
- **CISA ED 22-02**: Requirements for implementing phishing-resistant MFA

## License

Copyright (C) 2025 Ethan Troy <https://ethantroy.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.