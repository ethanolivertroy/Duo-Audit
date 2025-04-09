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