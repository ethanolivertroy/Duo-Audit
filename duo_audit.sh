#!/usr/bin/env bash
#
# duo_audit.sh
#
# A script to retrieve key Duo configuration for FedRAMP assessment.
# Requires:
#   - Bash 4+
#   - openssl (for HMAC-SHA1)
#   - curl
#   - jq (optional, for pretty-printing)
#   - zip
#
# Usage:
#   ./duo_audit.sh
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
OUTPUT_DIR="duo_audit_results_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

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
  if command -v jq &>/dev/null; then
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
# Example: Test connection by listing users
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
# 1) Retrieve user list
########################################
echo "Retrieving Duo users..."
duo_api_get "/admin/v1/users" "limit=50" "${OUTPUT_DIR}/users.json"

########################################
# 2) Retrieve administrator info
########################################
echo "Retrieving Duo administrators..."
duo_api_get "/admin/v1/admins" "" "${OUTPUT_DIR}/admins.json"

########################################
# 3) Retrieve phones (devices)
########################################
echo "Retrieving Duo phones..."
duo_api_get "/admin/v1/phones" "limit=50" "${OUTPUT_DIR}/phones.json"

########################################
# 4) Retrieve tokens (hardware tokens)
########################################
echo "Retrieving Duo tokens..."
duo_api_get "/admin/v1/tokens" "limit=50" "${OUTPUT_DIR}/tokens.json"

########################################
# 5) Retrieve logs or other endpoints
#    (Authentication logs, Telephony logs, etc.)
#    For large logs, you may need pagination
########################################
echo "Retrieving recent authentication logs (example)..."
duo_api_get "/admin/v2/logs/authentication" "limit=50" "${OUTPUT_DIR}/auth_logs.json"

########################################
# 6) Provide a text readme for any manual checks
########################################
tee "${OUTPUT_DIR}/manual_checks.txt" <<EOF
Some Duo FedRAMP checks may require manual UI confirmation:
- Phishing-resistant MFA or FIPS modules
- Policy configurations beyond basic user listing
- Subscription level / FedRAMP package validation

Refer to the Duo Admin Panel > Settings/Policy for additional details.
EOF

########################################
# Zip up results
########################################
ZIPFILE="duo_audit_${TIMESTAMP}.zip"
zip -r "$ZIPFILE" "$OUTPUT_DIR" >/dev/null

echo
echo "All checks complete!"
echo "Results directory: $OUTPUT_DIR"
echo "Zipped archive:    $ZIPFILE"