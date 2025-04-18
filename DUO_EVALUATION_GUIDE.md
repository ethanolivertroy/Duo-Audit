# Duo Security FedRAMP, NIST, and CISA Compliance Evaluation Guide

This guide provides a systematic approach to manually evaluate a Duo Security implementation for FedRAMP, NIST 800-53, and CISA compliance, complementing the automated `duo-audit.py` script. It follows the same assessment areas as the script but provides step-by-step instructions for a hands-on evaluation.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Authentication Methods & Phishing-Resistant MFA](#1-authentication-methods--phishing-resistant-mfa)
3. [Administrator Portal Security](#2-administrator-portal-security)
4. [FIPS Compliance](#3-fips-compliance)
5. [Authentication Policies](#4-authentication-policies)
6. [Administrator Role Review](#5-administrator-role-review)
7. [User Enrollment Status](#6-user-enrollment-status)
8. [Authentication Device Management](#7-authentication-device-management)
9. [Application & Integration Security](#8-application--integration-security)
10. [Authentication Logs & Monitoring](#9-authentication-logs--monitoring)
11. [Session Management & Timeout Settings](#10-session-management--timeout-settings)
12. [Device Trust Policies](#11-device-trust-policies)
13. [Federal Subscription Validation](#12-federal-subscription-validation)
14. [NIST 800-53 Control Matrix](#nist-800-53-control-matrix)
15. [Security Best Practices](#security-best-practices)

## Prerequisites

Before beginning your evaluation, ensure you have:

1. **Administrative access** to the Duo tenant being evaluated
2. **API credentials** with appropriate permissions:
   ```bash
   export DUO_API_HOSTNAME="api-12345.duosecurity.com"
   export DUO_INTEGRATION_KEY="your-integration-key"  
   export DUO_SECRET_KEY="your-secret-key"
   ```
3. **Required tools**:
   - Command line with `curl`, `jq`, and `python3` installed
   - Web browser for Admin Console access
   - Duo client Python library: `pip install duo_client`
4. **Documentation** of your organization's security requirements

> **Note:** Sections labeled "API Verification" contain Python code examples using the Duo Admin API Python client (`duo_client`). Ensure you run these examples with Python 3 and have the `duo_client` library installed.

### Alternative API Retrieval (curl + jq)

If you prefer not to use the Duo Python client, you can directly interact with the Duo Admin API using `curl` and `jq`. Ensure your environment variables are set:

```bash
export DUO_API_HOSTNAME="api-12345.duosecurity.com"
export DUO_INTEGRATION_KEY="your-integration-key"
export DUO_SECRET_KEY="your-secret-key"
```

#### Example Commands

```bash
# Retrieve account summary
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/info_summary" | jq . > account_info.json

# Retrieve users (limit to 1000)
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/users?limit=1000" | jq . > users.json

# Retrieve authentication devices (phones)
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/phones?limit=1000" | jq . > phones.json

# Retrieve hardware tokens
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/tokens?limit=1000" | jq . > tokens.json

# Retrieve policies (limit to 1000)
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/policies?limit=1000" | jq . > policies.json

# Retrieve settings
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/settings" | jq . > settings.json
```

## 1. Authentication Methods & Phishing-Resistant MFA

### Admin Console Steps
1. Navigate to **Authentication → Methods**
2. Document all enabled authentication methods
3. Verify phishing-resistant options (FIDO2/WebAuthn, hardware tokens) are enabled
4. Check which methods are marked as required vs optional
5. Go to **Settings → Security**
6. Check if any authentication methods have been restricted

### API Verification
Execute these commands and save the outputs for your documentation:

```python
# Using the Duo Admin API client
import duo_client
import json

# Create an Admin API client
admin_api = duo_client.Admin(
    ikey=DUO_INTEGRATION_KEY,
    skey=DUO_SECRET_KEY,
    host=DUO_API_HOSTNAME
)

# Get settings including authentication methods
settings = admin_api.get_settings()
with open('settings.json', 'w') as f:
    json.dump(settings, f, indent=2)

# Get authentication devices/methods in use
phones = admin_api.get_phones()
with open('phones.json', 'w') as f:
    json.dump(phones, f, indent=2)

# Get hardware tokens
tokens = admin_api.get_tokens()
with open('tokens.json', 'w') as f:
    json.dump(tokens, f, indent=2)
```
#### Alternative API Retrieval (curl + jq)

```bash
# Retrieve settings including authentication methods
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/settings" | jq . > settings.json

# Retrieve authentication devices (phones)
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/phones?limit=1000" | jq . > phones.json

# Retrieve hardware tokens
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/tokens?limit=1000" | jq . > tokens.json
```

### CISA Compliance Checklist
- [ ] FIDO2/WebAuthn authenticators are enabled (phishing-resistant)
- [ ] Hardware tokens are FIPS 140-2/140-3 validated (if required)
- [ ] SMS and phone call authentication methods are being phased out
- [ ] Mobile app-based push notifications require number matching or device verification
- [ ] Non-compliant authentication methods are documented with justification
- [ ] Privileged accounts use phishing-resistant methods

## 2. Administrator Portal Security

### Admin Console Steps
1. Navigate to **Settings → Administrators**
2. Review all administrator accounts
3. Check 2FA requirements for administrators
4. Review administrator activity logs
5. Check IP restrictions for admin access if applicable
6. Go to **Settings → Security**
7. Verify session timeout settings

### API Verification
```python
# Get administrator information
admins = admin_api.get_admins()
with open('admins.json', 'w') as f:
    json.dump(admins, f, indent=2)

# Get administrator logs
admin_logs = admin_api.get_administrator_log()
with open('admin_logs.json', 'w') as f:
    json.dump(admin_logs, f, indent=2)
```
#### Alternative API Retrieval (curl + jq)

```bash
# Retrieve administrators
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/admins?limit=1000" | jq . > admins.json

# Retrieve administrator logs
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/administrator_log?limit=1000" | jq . > admin_logs.json
```

### FedRAMP Requirements Checklist
- [ ] Administrator accounts are limited and follow least privilege
- [ ] Administrators use phishing-resistant MFA methods
- [ ] Session timeout is set appropriately (30 minutes or less)
- [ ] Administrator actions are logged and regularly reviewed
- [ ] Access to administrative functions follows separation of duties
- [ ] Administrator accounts are properly maintained and reviewed

## 3. FIPS Compliance
## Duo FIPS Status: API Endpoint Availability

**Summary:**
Duo Security does not currently provide an Admin API endpoint to programmatically check your Duo deployment’s FIPS status. Calls to methods like `get_fips_status` will fail with:
```
FAILED: 'Admin' object has no attribute 'get_fips_status'
```

---

### Details
- **No FIPS Status Endpoint:** The official [Duo Admin API documentation][1] lists no FIPS status endpoint.
- **Script Error Explained:** Attempting to call `get_fips_status` triggers a missing attribute error in the Duo Python client.
- **FIPS Compliance in Duo:** Determined by Duo Federal edition, OS‑level FIPS mode for components, and supported configurations as per the [Duo Federal Guide][2].

---

### What You Can Do
- **Manual Verification:** Review your subscription edition (Federal vs. Commercial) and OS FIPS mode for Duo proxies and agents.
- **Admin Console:** Inspect FIPS settings under your Federal subscription in the Duo Admin Panel.
- **Script Update:** Remove or comment out `get_fips_status` and related API calls (e.g., `get_trusted_endpoints_config`).

---

### Table: Duo API Capabilities vs. FIPS/Trusted Endpoints
| Feature                    | API Endpoint Available? | How to Check                      |
|----------------------------|-------------------------|-----------------------------------|
| FIPS Compliance            | No                      | Manual/documentation review       |
| Trusted Endpoints Config   | No (via Admin API)      | Admin Console, documentation      |
| User/Admin/Policy Retrieval | Yes                    | Duo Admin API                     |

---

### FIPS Compliance

### Admin Console Steps
1. Check if it's a Duo Federal instance
2. Navigate to **Applications**
3. Check if FIPS mode is enabled
4. Verify hardware tokens in use are FIPS validated
5. Check TLS settings and cipher suites


### FIPS Compliance Checklist
- [ ] Using Duo Federal for FedRAMP compliance
- [ ] FIPS mode is enabled where required
- [ ] Hardware tokens are FIPS 140-2/140-3 validated
- [ ] TLS 1.2+ with FIPS-approved cipher suites in use
- [ ] Cryptographic module validation documentation is available

## 4. Authentication Policies

### Admin Console Steps
1. Navigate to **Policies**
2. Review global policy settings
3. Check application-specific policies
4. Verify bypass codes and their usage policies
5. Review user groups and policy assignments
6. Check for any policy exclusions or exceptions

### API Verification
```python
# Get global policy
settings = admin_api.get_settings()
global_policy = settings.get('global_policy', {})
with open('global_policy.json', 'w') as f:
    json.dump(global_policy, f, indent=2)

# Get policies
policies = admin_api.get_policies()
with open('policies.json', 'w') as f:
    json.dump(policies, f, indent=2)

 # Get groups for policy assignment
groups = admin_api.get_groups()
with open('groups.json', 'w') as f:
    json.dump(groups, f, indent=2)
```
#### Alternative API Retrieval (curl + jq)

```bash
# Retrieve global settings (for policy info)
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/settings" | jq . > settings.json

# Retrieve policies
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/policies?limit=1000" | jq . > policies.json

# Retrieve groups
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/groups?limit=1000" | jq . > groups.json
```

### Policy Checklist
- [ ] Global policy requires MFA for all users
- [ ] Appropriate authentication factors are enforced
- [ ] Bypass codes are strictly controlled
- [ ] Policy exceptions are documented and justified
- [ ] Different policies for different security environments are appropriate
- [ ] Privileged access policies enforce stronger authentication

## 5. Administrator Role Review

### Admin Console Steps
1. Navigate to **Settings → Administrators**
2. Review each administrator for:
   - Role assignments
   - Last login time
   - Authentication methods enrolled
   - Contact information
3. Check for separation of duties among admin roles

### API Verification
```python
# Get administrators
admins = admin_api.get_admins()
with open('admins.json', 'w') as f:
    json.dump(admins, f, indent=2)
```
#### Alternative API Retrieval (curl + jq)

```bash
# Retrieve administrators
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/admins?limit=1000" | jq . > admins.json
```

### Admin Role Checklist
- [ ] Administrator accounts follow the principle of least privilege
- [ ] No unnecessary administrative access
- [ ] Administrator accounts use phishing-resistant MFA
- [ ] Privileged roles are properly documented
- [ ] Admin accounts are regularly reviewed
- [ ] Separation of duties is maintained

## 6. User Enrollment Status

### Admin Console Steps
1. Navigate to **Users**
2. Filter by status and enrollment status
3. Review users without MFA methods
4. Check for inactive users
5. Verify proper handling of departed users
6. Review bypass codes for compliance

### API Verification
```python
# Get all users
users = admin_api.get_users()
with open('users.json', 'w') as f:
    json.dump(users, f, indent=2)

# Analyze enrollment status (Python script example)
def analyze_enrollment():
    with open('users.json', 'r') as f:
        users = json.load(f)
    
    total = len(users)
    unenrolled = [u for u in users if u['status'] == 'active' and 
                 len(u.get('phones', [])) == 0 and len(u.get('tokens', [])) == 0]
    
    users_with_bypass = [u for u in users if len(u.get('bypass_codes', [])) > 0]
    
    print(f"Total users: {total}")
    print(f"Users without MFA: {len(unenrolled)}")
    print(f"Users with bypass codes: {len(users_with_bypass)}")
    
    with open('enrollment_analysis.txt', 'w') as f:
        f.write(f"Total users: {total}\n")
        f.write(f"Users without MFA: {len(unenrolled)}\n")
        f.write(f"Users with bypass codes: {len(users_with_bypass)}\n")
        
        f.write("\nUsers without MFA methods:\n")
        for user in unenrolled[:10]:  # Show first 10 for brevity
            f.write(f"- {user.get('username')} ({user.get('email')})\n")
        
        if len(unenrolled) > 10:
            f.write(f"...and {len(unenrolled) - 10} more\n")

analyze_enrollment()
```
#### Alternative API Retrieval (curl + jq)

```bash
# Retrieve users
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/users?limit=1000" | jq . > users.json
```

### User Management Checklist
- [ ] All active users have MFA enrolled
- [ ] Inactive users are properly handled/removed
- [ ] Bypass codes are strictly controlled
- [ ] User provisioning/deprovisioning procedures are documented
- [ ] Regular reviews of user enrollment status occur
- [ ] No unauthorized access exists

## 7. Authentication Device Management

### Admin Console Steps
1. Navigate to **Devices**
2. Review types of devices enrolled
3. Check device activation status
4. Verify hardware token inventory
5. Review any device restrictions
6. Check mobile application security settings

### API Verification
```python
# Get all phones/devices
phones = admin_api.get_phones()
with open('phones.json', 'w') as f:
    json.dump(phones, f, indent=2)

# Get all hardware tokens
tokens = admin_api.get_tokens()
with open('tokens.json', 'w') as f:
    json.dump(tokens, f, indent=2)

# Analyze device types (Python script example)
def analyze_devices():
    with open('phones.json', 'r') as f:
        phones = json.load(f)
    
    device_types = {}
    for phone in phones:
        device_type = phone.get('type', 'unknown')
        device_types[device_type] = device_types.get(device_type, 0) + 1
    
    with open('device_analysis.txt', 'w') as f:
        f.write("Device Type Distribution:\n")
        for dtype, count in device_types.items():
            f.write(f"- {dtype}: {count}\n")

analyze_devices()
```
#### Alternative API Retrieval (curl + jq)

```bash
# Retrieve phones/devices
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/phones?limit=1000" | jq . > phones.json

# Retrieve hardware tokens
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/tokens?limit=1000" | jq . > tokens.json
```

### Device Management Checklist
- [ ] All devices are properly inventoried
- [ ] Hardware tokens are FIPS validated where required
- [ ] Device activation process is secure
- [ ] Lost/stolen device procedures are documented
- [ ] Mobile applications enforce appropriate security settings
- [ ] Regular device audits are performed

## 8. Application & Integration Security

### Admin Console Steps
1. Navigate to **Applications**
2. Review all configured applications
3. Check authentication settings for each application
4. Verify application policies
5. Review application access settings
6. Check any custom integrations

### API Verification
```python
# Get integrations
integrations = admin_api.get_integrations()
with open('integrations.json', 'w') as f:
    json.dump(integrations, f, indent=2)
```
#### Alternative API Retrieval (curl + jq)

```bash
# Retrieve integrations
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/integrations?limit=1000" | jq . > integrations.json
```

### Application Security Checklist
- [ ] All applications are documented and approved
- [ ] Application-specific policies are appropriate for risk level
- [ ] Integration secrets are properly secured
- [ ] Application access is limited to authorized users
- [ ] No unauthorized applications or integrations exist

## 9. Authentication Logs & Monitoring

### Admin Console Steps
1. Navigate to **Reports → Authentication Log**
2. Review recent authentication events
3. Check for failed authentication attempts
4. Look for suspicious patterns
5. Check how logs are exported/monitored
6. Verify log retention settings

### API Verification
```python
# Get authentication logs (past 30 days)
import time
thirty_days_ago = int(time.time()) - (30 * 24 * 60 * 60)
auth_logs = admin_api.get_authentication_log(mintime=thirty_days_ago)
with open('auth_logs.json', 'w') as f:
    json.dump(auth_logs, f, indent=2)

# Analyze authentication failures (Python script example)
def analyze_auth_failures():
    with open('auth_logs.json', 'r') as f:
        logs = json.load(f)
    
    failures = [log for log in logs if log.get('result') != 'SUCCESS']
    
    failure_reasons = {}
    for failure in failures:
        reason = failure.get('result', 'unknown')
        failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
    
    with open('auth_failures.txt', 'w') as f:
        f.write(f"Total authentication failures: {len(failures)}\n\n")
        f.write("Failure reasons:\n")
        for reason, count in failure_reasons.items():
            f.write(f"- {reason}: {count}\n")

analyze_auth_failures()
```
#### Alternative API Retrieval (curl + jq)

```bash
# Retrieve authentication logs for past 30 days
MINTIME=$(($(date +%s) - 30*24*60*60))
curl -s -u "${DUO_INTEGRATION_KEY}:${DUO_SECRET_KEY}" \
  "https://${DUO_API_HOSTNAME}/admin/v1/authentication_log?mintime=${MINTIME}&limit=1000" | jq . > auth_logs.json
```

### Monitoring Checklist
- [ ] Authentication logs are exported to a SIEM or log management system
- [ ] Failed authentication attempts are tracked and investigated
- [ ] Log retention meets FedRAMP requirements (1 year online, 3 years archived)
- [ ] Authentication anomalies trigger alerts
- [ ] Regular log reviews are conducted

## 10. Session Management & Timeout Settings

### Admin Console Steps
1. Navigate to **Settings → Global Policy**
2. Check session lifetime settings
3. Review authentication session behavior
4. Check session expiration settings for applications
5. Verify idle timeout settings

### API Verification
```python
# Get settings including session lifetime
settings = admin_api.get_settings()
with open('settings.json', 'w') as f:
    json.dump(settings, f, indent=2)

# Extract session lifetime settings
auth_lifetime = settings.get('auth_lifetime', {})
with open('session_settings.txt', 'w') as f:
    f.write(f"Authentication lifetime settings:\n")
    f.write(f"- Session timeout: {auth_lifetime.get('auth_lifetime', 'Not set')} seconds\n")
    f.write(f"- Timeout enforced: {auth_lifetime.get('auth_lifetime_enabled', 'Not enabled')}\n")
    
    # Check compliance
    timeout_seconds = auth_lifetime.get('auth_lifetime', 0)
    is_compliant = timeout_seconds <= 30 * 60  # 30 minutes max for FedRAMP
    f.write(f"- FedRAMP compliant: {'YES' if is_compliant else 'NO'}\n")
    if not is_compliant:
        f.write(f"  (Exceeds 30 minutes - current setting: {timeout_seconds/60:.1f} minutes)\n")
```

### Session Management Checklist
- [ ] Session timeout set to 30 minutes or less (FedRAMP requirement)
- [ ] Authentication expiration is enforced
- [ ] Session termination behavior is appropriate
- [ ] Re-authentication is required after timeout
- [ ] Session settings are consistent across applications

## 11. Device Trust Policies

### Admin Console Steps
1. Navigate to **Endpoint Verification**
2. Check if endpoint verification is enabled
3. Review device health configurations
4. Check trusted endpoints policies
5. Verify how device posture affects authentication decisions

### API Verification
```python
# Get trusted endpoints configuration
try:
    trusted_endpoints = admin_api.get_trusted_endpoints_config()
    with open('trusted_endpoints.json', 'w') as f:
        json.dump(trusted_endpoints, f, indent=2)
except:
    print("Trusted endpoints not available or not configured")
```

### Device Trust Checklist
- [ ] Device posture assessment is enabled where appropriate
- [ ] Device trust settings align with organization security policy
- [ ] Compromised device detection is configured
- [ ] Health-check requirements are appropriate
- [ ] Device trust affects authentication decisions appropriately

## 12. Federal Subscription Validation

### Manual Verification
1. Confirm you are using Duo Federal edition
2. Verify FIPS mode is enabled
3. Review any FedRAMP documentation specific to your Duo instance
4. Check procurement documents reference FedRAMP compliance
5. Verify with your security team that the appropriate FedRAMP package is in place

### FedRAMP Compliance Checklist
- [ ] Duo Federal edition is in use
- [ ] Written confirmation from Duo regarding FedRAMP environment
- [ ] FIPS 140-2/140-3 validated modules are enabled
- [ ] FedRAMP package documentation is available
- [ ] Contractual requirements for FedRAMP are met
- [ ] All FedRAMP-specific controls are implemented

## NIST 800-53 Control Matrix

The following matrix maps key Duo settings to NIST 800-53 controls:

| Control | Description | Evaluation Areas | Duo Settings to Review |
|---------|-------------|------------------|-------------------------|
| **AC-2** | Account Management | User enrollment, admin accounts | User provisioning/deprovisioning, inactive users, administrator settings |
| **AC-3** | Access Enforcement | Policies, application access | Policy enforcement, application settings, group assignments |
| **AC-7** | Unsuccessful Login Attempts | Authentication logs | Failed authentication attempts, lockout policies |
| **AC-12** | Session Termination | Session settings | Session timeout, re-authentication requirements |
| **IA-2** | Identification and Authentication | MFA methods, policies | MFA enforcement, authentication methods, phishing-resistant options |
| **IA-5** | Authenticator Management | Tokens, device management | Hardware token management, device enrollment/activation |
| **SC-8** | Transmission Confidentiality | FIPS settings, TLS | FIPS mode, encryption settings |
| **SC-28** | Protection of Information at Rest | FIPS compliance | FIPS validation, data protection |
| **AU-2** | Audit Events | Authentication logs | Log types collected, authentication activity tracking |
| **CM-8** | Information System Component Inventory | Device management | Device inventory, hardware token tracking |

## Security Best Practices

Below are recommended security best practices to complement the compliance checks above:

### 1. API Key & Secret Management
- Use a dedicated, least-privilege integration key (read-only or service account) for audits.
- Store Duo API credentials in a secure vault or excluded `.env` file; rotate keys regularly and document active keys.

### 2. Least Privilege & Admin Roles
- Map internal roles to Duo built-in admin roles (User Manager, Read-Only Auditor, Help Desk Operator).
- Restrict Admin Panel access via IP allowlists or VPNs; enforce separation of duties with distinct high-privilege roles.
- Conduct quarterly reviews of admin role assignments.

### 3. Network & Access Controls
- Limit Admin Console access to corporate IP ranges via Duo IP restrictions or network firewalls.
- Use Duo Device Trust or Network Zones to restrict authentication to approved subnets or endpoints.

### 4. MFA & Authentication Policies
- Audit bypass code generation and usage: who can create codes, number outstanding, frequency of use.
- Verify no unconditional allow rules or policy exceptions bypassing MFA requirements.
- Implement adaptive authentication policies (e.g., risk-based step-up, geolocation blocking).

### 5. Device Security & Endpoint Verification
- Enable and monitor Duo Endpoint Verification to enforce disk encryption, OS patch status, and health checks.
- Inventory managed vs. unmanaged endpoints; remediate any blind spots.

### 6. Logging, Monitoring & Alerting
- Forward Duo Admin API logs and authentication logs to your SIEM (e.g., Splunk, Elastic, Datadog) for centralized monitoring.
- Define key alerts: multiple bypass code events, spikes in failed logins, new high-privilege admin creations.
- Ensure log retention meets regulatory requirements (e.g., FedRAMP 90 days online; 1 year archived).

### 7. Incident Response & Maturity
- Document playbooks for critical incidents (e.g., integration key compromise: rotate keys, revoke tokens, re-enroll users).
- Conduct regular tabletop exercises on MFA bypass, credential compromise, and device breach scenarios.

### 8. Change-Management & Continuous Compliance
- Schedule quarterly reviews of policies and configurations using this guide; track findings in a standardized log (columns: Control, Status, Risk, Owner, Due Date).

### 9. Integration-Specific Considerations
- For Duo Unix, AD Connector, or Auth Proxy deployments, verify FIPS/TLS settings and versions in configuration files (e.g., `/etc/duo/pam_duo.conf`), and keep configs under version control.
- Reference official component docs for up-to-date security recommendations.

### 10. References & Further Reading
- Duo Service Accounts & API Best Practices: https://duo.com/docs/adminapi
- Duo Endpoint Verification Admin Guide: https://duo.com/docs/trusted-endpoints
- Duo Authentication Proxy Security: https://duo.com/docs/authproxy-reference
- NIST SP 800-53 Control Catalog: https://csrc.nist.gov/projects/800-53

## Documentation Template

For each section evaluated, document:
1. **Current Configuration**: Findings from the Admin Console and API checks
2. **Compliance Status**: Compliant, Partially Compliant, Non-Compliant
3. **Gaps**: Any identified compliance gaps
4. **Recommendations**: Specific actions to address gaps
5. **Evidence**: Screenshots or API outputs demonstrating compliance

## Final Compliance Report

Compile your findings into a comprehensive compliance report that includes:
1. Executive summary
2. Scope of evaluation
3. Methodology
4. Detailed findings by section
5. Gap analysis
6. Remediation plan
7. Appendices with evidence

## References

- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [CISA Emergency Directive 22-02](https://www.cisa.gov/directives/emergency-directive-22-02)
- [FedRAMP Compliance](https://www.fedramp.gov/)
- [Duo Federal Documentation](https://duo.com/solutions/government)
- [NIST FIPS 140-2/140-3](https://csrc.nist.gov/Projects/cryptographic-module-validation-program)

[1]: https://duo.com/docs/adminapi
[2]: https://duo.com/docs/duo-federal-guide