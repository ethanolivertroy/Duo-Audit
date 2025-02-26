#!/usr/bin/env bash
#
# duo_fedramp_audit.sh
#
# A comprehensive script to evaluate Duo Security for FedRAMP compliance.
# Extended from original duo_audit.sh to include additional compliance checks.
#
# Requires:
#   - Bash 4+
#   - openssl (for HMAC-SHA1)
#   - curl
#   - jq (optional, for pretty-printing)
#   - zip
#
# Usage:
#   ./duo_fedramp_audit.sh
#   You will be prompted for your Duo API credentials.

set -euo pipefail

# Check for prerequisites
if ! command -v openssl &>/dev/null; then
  echo "ERROR: 'openssl' is not installed or not in PATH." >&2
  exit 1
fi

if ! command -v curl &>/dev/null; then
  echo "ERROR: 'curl' is not installed or not in PATH." >&2
  exit 1
fi

if ! command -v zip &>/dev/null; then
  echo "ERROR: 'zip' is not installed or not in PATH." >&2
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "WARNING: 'jq' is not installed. JSON output won't be pretty-printed."
  HAS_JQ=false
else
  HAS_JQ=true
fi

# Prompt for Duo credentials if not already set as env vars
read -p "Enter your Duo API Hostname (e.g., api-xxxx.duosecurity.com): " DUO_API_HOSTNAME
read -p "Enter your Duo Integration Key: " DUO_INTEGRATION_KEY
read -sp "Enter your Duo Secret Key: " DUO_SECRET_KEY
echo

# Validate
if [ -z "$DUO_API_HOSTNAME" ] || [ -z "$DUO_INTEGRATION_KEY" ] || [ -z "$DUO_SECRET_KEY" ]; then
  echo "ERROR: Missing Duo credentials."
  exit 1
fi

# Create output directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="duo_fedramp_audit_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/raw_data"
mkdir -p "$OUTPUT_DIR/compliance_reports"

echo "Running Duo FedRAMP assessment checks..."
echo "Outputs will be saved to: $OUTPUT_DIR"

########################################
# Helper: Generate HMAC-SHA1 signature
########################################
# - see https://duo.com/docs/adminapi#authentication for details
duo_sign_request() {
  local method="$1"    # GET/POST
  local path="$2"      # /admin/v1/users
  local params="$3"    # query string (e.g., "limit=10" or "" for none)
  local date_string="$4" # RFC1123 date, e.g., "Tue, 21 Jan 2025 20:55:55 -0000"

  # Canonical string: <date>\n<method>\n<host>\n<path>\n<params>
  local canon="${date_string}\n${method}\n${DUO_API_HOSTNAME}\n${path}\n${params}"

  # HMAC-SHA1 of canonical string using SECRET_KEY
  # Output base64-encoded signature
  local sig
  sig=$(printf "%s" "$canon" | openssl dgst -sha1 -hmac "$DUO_SECRET_KEY" -binary | openssl base64)
  echo "$sig"
}

########################################
# Helper function: duo_api_get
#   - signs and executes GET request
########################################
duo_api_get() {
  local path="$1"         # e.g. /admin/v1/users
  local query="$2"        # e.g. "limit=10"
  local output_file="$3"  # where to save JSON

  local method="GET"
  local date_string
  date_string=$(date -u +"%a, %d %b %Y %H:%M:%S -0000")
  local sig
  sig=$(duo_sign_request "$method" "$path" "$query" "$date_string")

  # Build Authorization header
  # format: "Basic <base64-encoded 'INTEGRATION_KEY:signature'>"
  local auth_string
  auth_string="${DUO_INTEGRATION_KEY}:${sig}"
  local auth_header
  auth_header="Basic $(echo -n "$auth_string" | openssl base64)"

  # Full URL
  local url="https://${DUO_API_HOSTNAME}${path}"
  if [ -n "$query" ]; then
    url="${url}?${query}"
  fi

  # Perform GET
  # Add 'Date' and 'Authorization' headers required by Duo
  # Save output to $output_file
  local tmpfile
  tmpfile=$(mktemp)
  local http_code
  http_code=$(curl -s -w "%{http_code}" -o "$tmpfile" \
    -X GET \
    -H "Host: ${DUO_API_HOSTNAME}" \
    -H "Date: ${date_string}" \
    -H "Authorization: ${auth_header}" \
    "$url")

  if [ "$http_code" -ne 200 ]; then
    echo "Warning: GET $path failed with HTTP $http_code"
    echo "[]" > "$output_file"
    rm -f "$tmpfile"
    return 1
  fi

  # If 'jq' is installed, we'll pretty-print into $output_file
  if $HAS_JQ; then
    if ! jq '.' "$tmpfile" > "$output_file" 2>/dev/null; then
      echo "Warning: Invalid JSON from $path"
      echo "[]" > "$output_file"
    fi
  else
    # If no jq, just store raw
    mv "$tmpfile" "$output_file"
  fi
  rm -f "$tmpfile"
}

########################################
# Test connection by listing users
########################################
TEST_FILE=$(mktemp)
if ! duo_api_get "/admin/v1/users" "limit=1" "$TEST_FILE"; then
  echo "ERROR: Failed to connect to Duo Admin API. Please verify credentials."
  cat "$TEST_FILE"
  rm -f "$TEST_FILE"
  exit 1
fi
rm -f "$TEST_FILE"
echo "Duo Admin API connection successful!"

########################################
# Retrieve basic data
########################################
echo "Retrieving Duo configuration data..."

# Users
echo "  - Retrieving users..."
duo_api_get "/admin/v1/users" "limit=1000" "${OUTPUT_DIR}/raw_data/users.json"

# Administrators
echo "  - Retrieving administrators..."
duo_api_get "/admin/v1/admins" "" "${OUTPUT_DIR}/raw_data/admins.json"

# Phones/devices
echo "  - Retrieving phones/devices..."
duo_api_get "/admin/v1/phones" "limit=1000" "${OUTPUT_DIR}/raw_data/phones.json"

# Hardware tokens
echo "  - Retrieving hardware tokens..."
duo_api_get "/admin/v1/tokens" "limit=1000" "${OUTPUT_DIR}/raw_data/tokens.json"

# Authentication logs - get larger sample for compliance analysis
echo "  - Retrieving authentication logs (last 30 days)..."
# Unix timestamp for 30 days ago
THIRTY_DAYS_AGO=$(date -d "30 days ago" +%s)
duo_api_get "/admin/v2/logs/authentication" "mintime=${THIRTY_DAYS_AGO}&limit=1000" "${OUTPUT_DIR}/raw_data/auth_logs.json"

# Admin logs - crucial for compliance auditing
echo "  - Retrieving admin activity logs..."
duo_api_get "/admin/v1/logs/administrator" "limit=1000" "${OUTPUT_DIR}/raw_data/admin_logs.json"

# Policy settings - critical for FedRAMP evaluation
echo "  - Retrieving policy settings..."
duo_api_get "/admin/v1/settings" "" "${OUTPUT_DIR}/raw_data/settings.json"

# Integrations - understand what systems are connected
echo "  - Retrieving integrations..."
duo_api_get "/admin/v1/integrations" "" "${OUTPUT_DIR}/raw_data/integrations.json"

# Trusted endpoints - device security posture
echo "  - Retrieving trusted endpoints configuration..."
duo_api_get "/admin/v1/trusted_endpoints/config" "" "${OUTPUT_DIR}/raw_data/trusted_endpoints.json"

# Groups - understand role-based organization
echo "  - Retrieving groups..."
duo_api_get "/admin/v1/groups" "" "${OUTPUT_DIR}/raw_data/groups.json"

########################################
# Generate FedRAMP compliance reports
########################################
echo "Generating FedRAMP compliance reports..."

# Analysis function for jq-enabled environments
analyze_compliance() {
  if ! $HAS_JQ; then
    echo "Skipping detailed compliance analysis (jq not installed)"
    return
  fi

  echo "Analyzing Duo configuration for FedRAMP compliance..."
  
  # 1. MFA Policy Analysis
  echo "  - Analyzing MFA policies..."
  if $HAS_JQ; then
    jq -r '
      "FedRAMP MFA Policy Assessment:\n" +
      "================================\n" +
      "Global Policy Settings:\n" +
      (if .response.global_policy then
        "- MFA Required: " + (.response.global_policy.require_mfa | tostring) + "\n" +
        "- FIDO2 Enforced: " + (.response.global_policy.fido2_enforced | tostring) + "\n" +
        "- Hardware Token Required: " + (.response.global_policy.hardware_token_required | tostring)
      else
        "No global policy found"
      end)
    ' "${OUTPUT_DIR}/raw_data/settings.json" > "${OUTPUT_DIR}/compliance_reports/mfa_policy_report.txt"
  fi

  # 2. Authentication Methods Analysis
  echo "  - Analyzing authentication methods in use..."
  if $HAS_JQ; then
    jq -r '
      "FedRAMP Authentication Method Assessment:\n" +
      "========================================\n" +
      "Methods used in last 30 days:\n" +
      (.response // [] | group_by(.factor) | map({
        method: .[0].factor,
        count: length
      }) | sort_by(.count) | reverse | .[] | "- " + .method + ": " + (.count | tostring) + " authentications")
    ' "${OUTPUT_DIR}/raw_data/auth_logs.json" > "${OUTPUT_DIR}/compliance_reports/auth_methods_report.txt"
  fi

  # 3. Administrator Access Report
  echo "  - Analyzing administrator access patterns..."
  if $HAS_JQ; then
    jq -r '
      "FedRAMP Administrator Access Report:\n" +
      "==================================\n" +
      "Administrator Count: " + (.response | length | tostring) + "\n\n" +
      "Administrator Details:\n" +
      (.response | sort_by(.name) | .[] | 
        "- " + .name + " (" + .email + ")\n" +
        "  • Role: " + .role + "\n" +
        "  • Status: " + .status + "\n" +
        "  • 2FA: " + (.valid_secs_2fa | tostring))
    ' "${OUTPUT_DIR}/raw_data/admins.json" > "${OUTPUT_DIR}/compliance_reports/admin_access_report.txt"
  fi

  # 4. User Analysis Report (focusing on non-compliant users)
  echo "  - Identifying users without proper MFA..."
  if $HAS_JQ; then
    jq -r '
      "FedRAMP User Compliance Report:\n" +
      "=============================\n" +
      "Total Users: " + (.response | length | tostring) + "\n" +
      "Users without phones: " + (.response | map(select(.phones | length == 0)) | length | tostring) + "\n" +
      "Users with bypass codes: " + (.response | map(select(.bypass_codes | length > 0)) | length | tostring) + "\n\n" +
      "List of users without proper MFA setup:\n" +
      (.response | map(select(.phones | length == 0)) | .[] | "- " + .username + " (" + .email + ")")
    ' "${OUTPUT_DIR}/raw_data/users.json" > "${OUTPUT_DIR}/compliance_reports/user_compliance_report.txt"
  fi

  # 5. Authentication Failure Analysis
  echo "  - Analyzing authentication failures..."
  if $HAS_JQ; then
    jq -r '
      "FedRAMP Authentication Failure Report:\n" +
      "====================================\n" +
      "Failed authentications in last 30 days: " + 
      (.response | map(select(.result != "SUCCESS")) | length | tostring) + "\n\n" +
      "Failure breakdown by reason:\n" +
      (.response | map(select(.result != "SUCCESS")) | group_by(.result) | map({
        reason: .[0].result,
        count: length
      }) | sort_by(.count) | reverse | .[] | "- " + .reason + ": " + (.count | tostring))
    ' "${OUTPUT_DIR}/raw_data/auth_logs.json" > "${OUTPUT_DIR}/compliance_reports/auth_failures_report.txt"
  fi
}

# Run compliance analysis
analyze_compliance

########################################
# FedRAMP Compliance Checklist
########################################
cat > "${OUTPUT_DIR}/compliance_reports/fedramp_checklist.txt" << EOF
DUO SECURITY FEDRAMP COMPLIANCE CHECKLIST
=========================================
Date of assessment: $(date)

REQUIRED CONTROLS CHECKLIST:
---------------------------
[ ] AC-2: Account Management
    - Verify admin accounts are limited and reviewed
    - Check user provisioning/deprovisioning procedures

[ ] AC-12: Session Termination
    - Verify session timeout settings

[ ] IA-2: Identification and Authentication (Organizational Users)
    - Verify MFA enforcement for all users
    - Confirm use of FIPS 140-2 compliant authenticators

[ ] IA-5: Authenticator Management
    - Verify password policies
    - Check hardware token management

[ ] AU-2: Audit Events
    - Verify authentication logs retention
    - Confirm admin action logging

[ ] SC-28: Protection of Information at Rest
    - Verify encryption of stored authentication data

IMPLEMENTATION STATUS:
--------------------
Review the raw data files and generated reports to complete this checklist.
Key files to check:
- settings.json: For global policy settings
- auth_logs.json: For authentication patterns
- admin_logs.json: For administrative actions
- users.json & phones.json: For user enrollment status

COMPLIANCE NOTES:
---------------
1. Duo Federal must be used for FedRAMP compliance
2. FIPS 140-2 validated modules must be enabled
3. Phishing-resistant authentication methods should be enforced
4. Admin accounts must use hardware tokens

DOCUMENTATION REQUIREMENTS:
-------------------------
- SSP (System Security Plan) should include Duo configuration
- Incident response plan should include Duo MFA compromise procedures
- Contingency plan should address Duo service disruption
EOF

########################################
# Executive Summary
########################################
cat > "${OUTPUT_DIR}/compliance_reports/executive_summary.txt" << EOF
DUO SECURITY FEDRAMP COMPLIANCE ASSESSMENT
==========================================
Date: $(date)
Assessment ID: duo-fedramp-${TIMESTAMP}

EXECUTIVE SUMMARY
----------------
This automated assessment collected configuration data from your Duo Security
instance to evaluate FedRAMP compliance readiness. The assessment focused on:

1. Authentication policies
2. Administrator access controls
3. User enrollment status
4. Authentication logs
5. Two-factor authentication methods in use

NEXT STEPS
---------
1. Review the detailed reports in the 'compliance_reports' directory
2. Complete the FedRAMP checklist
3. Address any compliance gaps identified
4. Document your Duo configuration in your System Security Plan (SSP)
5. Schedule a follow-up assessment after remediation

KEY RECOMMENDATIONS
-----------------
1. Ensure all administrators use hardware tokens or WebAuthn
2. Validate that bypass codes are strictly controlled
3. Confirm your Duo edition supports FedRAMP compliance
4. Verify FIPS 140-2 validated cryptographic modules are enabled
5. Document any approved exceptions to MFA requirements

For questions on this assessment, please contact your security team.
EOF

########################################
# Zip up results
########################################
ZIPFILE="duo_fedramp_audit_${TIMESTAMP}.zip"
echo "Creating archive of all assessment data..."
zip -r "$ZIPFILE" "$OUTPUT_DIR" >/dev/null

echo
echo "All FedRAMP compliance checks complete!"
echo "Results directory: $OUTPUT_DIR"
echo "Zipped archive:    $ZIPFILE"
echo
echo "Be sure to review the generated compliance reports in ${OUTPUT_DIR}/compliance_reports/"
echo "and complete the FedRAMP checklist with your findings."