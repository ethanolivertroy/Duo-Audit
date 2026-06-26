#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
duo-audit.py

Evaluate Duo Security against FedRAMP 20x Key Security Indicators (KSIs),
legacy FedRAMP / NIST SP 800-53 Rev 5 control themes, NIST SP 800-63B,
and CISA phishing-resistant MFA expectations.

Focuses on MFA enforcement, phishing-resistant authenticators, least privilege
for Duo admins, and machine-readable evidence suitable for continuous validation.

Author: Ethan Troy <https://ethantroy.dev>
License: Unlicense (public domain dedication) — see LICENSE

Requires:
  - Python 3.8+
  - duo_client Python library
  - colorama, tabulate (optional but recommended)

Usage:
  python3 duo-audit.py
  You will be prompted for your Duo API credentials.
"""

import os
import sys
import json
import time
import getpass
import datetime
import zipfile
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple
from functools import wraps
from time import sleep

try:
    import duo_client
except ImportError:
    print("Error: Required package 'duo_client' not found.")
    print("Please install it using: pip install duo_client")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback if colorama is not installed
    class ForeStub:
        def __getattr__(self, name):
            return ""
    class StyleStub:
        def __getattr__(self, name):
            return ""
    Fore = ForeStub()
    Style = StyleStub()

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# Script version information
SCRIPT_VERSION = "1.3.0"
SCRIPT_DATE = "2026-06-25"

# Official FedRAMP Consolidated Rules for 2026 — KSI-IAM identifiers and outcome text.
# Source of truth: https://github.com/FedRAMP/2026-markdown
#   providers/20x/key-security-indicators/identity-and-access-management.md
# (machine-generated from FedRAMP Machine-Readable Rules; launched 2026-06-24 in that corpus)
FEDRAMP_2026_KSI_IAM = (
    (
        "KSI-IAM-AAM",
        "Automating Account Management",
        "The lifecycle and privileges of all accounts, roles, and groups are securely managed using automation.",
    ),
    (
        "KSI-IAM-APM",
        "Adopting Passwordless Methods",
        "Secure passwordless methods are used for user authentication and authorization when feasible, "
        "otherwise strong passwords with phishing-resistant MFA is used.",
    ),
    (
        "KSI-IAM-ELP",
        "Ensuring Least Privilege",
        "Identity and access management measures are used and persistently reviewed to ensure each user "
        "or device can only access the resources they need.",
    ),
    (
        "KSI-IAM-JIT",
        "Authorizing Just-in-Time",
        "A least-privileged, role and attribute-based, and just-in-time security authorization model is "
        "used and persistently reviewed for all user and non-user accounts and services.",
    ),
    (
        "KSI-IAM-SNU",
        "Securing Non-User Authentication",
        "Appropriately secure authentication methods are used and persistently reviewed for non-user "
        "accounts and services.",
    ),
    (
        "KSI-IAM-SUS",
        "Responding to Suspicious Activity",
        "Accounts with privileged access are disabled or otherwise secured in response to suspicious activity.",
    ),
)

FEDRAMP_2026_MARKDOWN_IAM = (
    "https://github.com/FedRAMP/2026-markdown/blob/main/"
    "providers/20x/key-security-indicators/identity-and-access-management.md"
)
FEDRAMP_2026_MARKDOWN_KSI_INDEX = (
    "https://github.com/FedRAMP/2026-markdown/blob/main/"
    "providers/20x/key-security-indicators/index.md"
)
FEDRAMP_2026_MARKDOWN_REPO = "https://github.com/FedRAMP/2026-markdown"

# Pinned revision of FedRAMP/2026-markdown used for KSI ID/outcome text in this release.
# Refresh: GET https://api.github.com/repos/FedRAMP/2026-markdown/commits/main
FEDRAMP_2026_MARKDOWN_PIN = {
    "repository": "https://github.com/FedRAMP/2026-markdown",
    "ref": "main",
    "commit_sha": "ea5e4cbd2cef45256276a882060de96cc507cda3",
    "commit_date_utc": "2026-06-26T01:21:53Z",
    "iam_path": "providers/20x/key-security-indicators/identity-and-access-management.md",
    "tree_url": (
        "https://github.com/FedRAMP/2026-markdown/tree/"
        "ea5e4cbd2cef45256276a882060de96cc507cda3"
    ),
    "iam_blob_url": (
        "https://github.com/FedRAMP/2026-markdown/blob/"
        "ea5e4cbd2cef45256276a882060de96cc507cda3/"
        "providers/20x/key-security-indicators/identity-and-access-management.md"
    ),
}


# API Rate limiting settings
MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 1  # seconds
BACKOFF_FACTOR = 2
RATE_LIMIT_DELAY = 60  # seconds to wait when rate limited
API_CALL_DELAY = 0.1  # seconds between API calls to avoid hitting rate limits

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def retry_with_backoff(max_retries: int = MAX_RETRIES, 
                      initial_delay: float = INITIAL_RETRY_DELAY,
                      backoff_factor: float = BACKOFF_FACTOR):
    """Decorator to retry API calls with exponential backoff."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            delay = initial_delay
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except duo_client.DuoException as e:
                    last_exception = e
                    error_msg = str(e)
                    
                    # Check for rate limiting (various error messages)
                    if any(indicator in error_msg.lower() for indicator in 
                          ["rate limit", "429", "too many requests", "quota exceeded"]):
                        wait_time = RATE_LIMIT_DELAY
                        # Try to extract wait time from error message if available
                        import re
                        wait_match = re.search(r'(\d+)\s*seconds?', error_msg)
                        if wait_match:
                            wait_time = int(wait_match.group(1)) + 5  # Add 5 seconds buffer
                        
                        logger.warning(f"Rate limit hit. Waiting {wait_time} seconds...")
                        print(f"{Fore.YELLOW}⚠️  Rate limit reached. Waiting {wait_time} seconds before retrying...")
                        sleep(wait_time)
                        continue
                    
                    # For other errors, use exponential backoff
                    if attempt < max_retries - 1:
                        logger.warning(f"API call failed (attempt {attempt + 1}/{max_retries}): {error_msg}")
                        logger.info(f"Retrying in {delay} seconds...")
                        sleep(delay)
                        delay *= backoff_factor
                    else:
                        logger.error(f"API call failed after {max_retries} attempts: {error_msg}")
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        logger.warning(f"Unexpected error (attempt {attempt + 1}/{max_retries}): {str(e)}")
                        sleep(delay)
                        delay *= backoff_factor
                    else:
                        logger.error(f"Unexpected error after {max_retries} attempts: {str(e)}")
            
            raise last_exception
        return wrapper
    return decorator

def validate_api_response(data: Any, expected_type: type = None, required_fields: List[str] = None) -> Any:
    """Validate and sanitize API response data."""
    if data is None:
        logger.warning("Received None response from API")
        return [] if expected_type == list else {}
    
    # Type validation
    if expected_type and not isinstance(data, expected_type):
        logger.warning(f"Expected {expected_type.__name__} but got {type(data).__name__}")
        return [] if expected_type == list else {}
    
    # For list responses, validate each item
    if isinstance(data, list):
        validated_items = []
        for item in data:
            if isinstance(item, dict):
                # Sanitize dict items
                sanitized_item = {k: v for k, v in item.items() if v is not None}
                validated_items.append(sanitized_item)
            else:
                validated_items.append(item)
        return validated_items
    
    # For dict responses, check required fields
    if isinstance(data, dict):
        if required_fields:
            missing_fields = [field for field in required_fields if field not in data]
            if missing_fields:
                logger.warning(f"Missing required fields: {missing_fields}")
        
        # Sanitize dict - remove None values
        return {k: v for k, v in data.items() if v is not None}
    
    return data

def safe_get(data: Union[Dict, List], key: Union[str, int], default: Any = None) -> Any:
    """Safely get a value from a dict or list with a default."""
    try:
        if isinstance(data, dict):
            return data.get(key, default)
        elif isinstance(data, list) and isinstance(key, int):
            return data[key] if 0 <= key < len(data) else default
        else:
            return default
    except (KeyError, IndexError, TypeError):
        return default

def print_banner():
    """Display a stylish banner for the script."""
    banner = rf"""
 _______   __    __    ______           ___      __    __   _______   __  .___________.
|       \ |  |  |  |  /  __  \         /   \    |  |  |  | |       \ |  | |           |
|  .--.  ||  |  |  | |  |  |  |       /  ^  \   |  |  |  | |  .--.  ||  | `---|  |----`
|  |  |  ||  |  |  | |  |  |  |      /  /_\  \  |  |  |  | |  |  |  ||  |     |  |
|  '--'  ||  `--'  | |  `--'  |     /  _____  \ |  `--'  | |  '--'  ||  |     |  |
|_______/  \______/   \______/     /__/     \__\ \______/  |_______/ |__|     |__|

{Fore.CYAN}Duo Audit v{SCRIPT_VERSION}
{Fore.CYAN}FedRAMP 20x KSIs | NIST SP 800-63B | CISA Directives
{Fore.CYAN}Enhanced with retry logic and data validation
"""
    print(banner)

def get_credentials() -> Tuple[str, str, str]:
    """Prompt for and return Duo Admin API credentials."""
    print(f"{Style.BRIGHT}Please enter your Duo Admin API credentials:")
    host = input("Enter your Duo API Hostname (e.g., api-xxxx.duosecurity.com): ")
    ikey = input("Enter your Duo Integration Key: ")
    skey = getpass.getpass("Enter your Duo Secret Key: ")
    
    if not host or not ikey or not skey:
        print(f"{Fore.RED}Error: Missing Duo credentials.")
        sys.exit(1)
    
    # Basic hostname validation
    import re
    if not re.match(r'^api-[a-zA-Z0-9]+\.duosecurity\.com$', host):
        print(f"{Fore.YELLOW}Warning: Hostname doesn't match expected pattern (api-xxxx.duosecurity.com)")
        print(f"{Fore.YELLOW}Proceeding anyway, but please verify your hostname is correct.")
    
    return host, ikey, skey

def create_admin_client(host: str, ikey: str, skey: str) -> duo_client.Admin:
    """Create and return a Duo Admin API client."""
    return duo_client.Admin(ikey=ikey, skey=skey, host=host)

@retry_with_backoff()
def test_connection(admin_api: duo_client.Admin) -> bool:
    """Test the connection to the Duo Admin API."""
    print(f"\n{Fore.CYAN}Testing Duo Admin API connection...")
    try:
        # Try to get a single user to verify connection
        result = admin_api.get_users(limit=1)
        # Validate the response
        validate_api_response(result, expected_type=list)
        print(f"{Fore.GREEN}✅ Duo Admin API connection successful!")
        return True
    except Exception as e:
        print(f"{Fore.RED}❌ Failed to connect to Duo Admin API: {str(e)}")
        logger.error(f"Connection test failed: {str(e)}")
        return False

def setup_output_dirs(base_dir: str = None) -> str:
    """Create and return the output directory structure."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"duo_compliance_audit_{timestamp}" if not base_dir else base_dir
    
    directories = [
        output_dir,
        f"{output_dir}/raw_data",
        f"{output_dir}/compliance_reports",
        f"{output_dir}/visualizations"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    print(f"{Fore.CYAN}Running Duo compliance assessment...")
    print(f"Outputs will be saved to: {output_dir}")
    
    return output_dir

def retrieve_duo_data(admin_api: duo_client.Admin, output_dir: str) -> Dict[str, Any]:
    """Retrieve all necessary data from Duo and save to files."""
    print(f"\n{Fore.CYAN}Retrieving Duo configuration data...")
    data_dir = f"{output_dir}/raw_data"
    
    # Data structure to hold all retrieved information
    duo_data = {}
    
    # Helper function to get and save API data with retry and validation
    @retry_with_backoff()
    def get_and_save(endpoint_name: str, method_name: str, *args, **kwargs) -> Any:
        print(f"  - Retrieving {endpoint_name}...")
        try:
            method = getattr(admin_api, method_name)
            data = method(*args, **kwargs)
            
            # Validate the response based on endpoint type
            if endpoint_name in ["users", "admins", "phones", "tokens", "auth logs", "admin logs", 
                               "integrations", "groups", "policies"]:
                data = validate_api_response(data, expected_type=list)
            elif endpoint_name in ["account info", "settings", "policy details", "telephony"]:
                data = validate_api_response(data, expected_type=dict)
            else:
                data = validate_api_response(data)
            
            # Save to file
            filename = f"{data_dir}/{endpoint_name.lower().replace(' ', '_')}.json"
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
            
            print(f"    {Fore.GREEN}SUCCESS")
            # Add small delay between API calls to avoid rate limits
            sleep(API_CALL_DELAY)
            return data
        except Exception as e:
            print(f"    {Fore.RED}FAILED: {str(e)}")
            logger.error(f"Failed to retrieve {endpoint_name}: {str(e)}")
            # Save empty data to maintain file structure
            filename = f"{data_dir}/{endpoint_name.lower().replace(' ', '_')}.json"
            with open(filename, "w") as f:
                json.dump([] if endpoint_name in ["users", "admins", "phones", "tokens", "auth logs", 
                                                 "admin logs", "integrations", "groups", "policies"] else {}, f)
            return [] if endpoint_name in ["users", "admins", "phones", "tokens", "auth logs", 
                                         "admin logs", "integrations", "groups", "policies"] else {}
    
    # 1. Account info
    print(f"  {Style.BRIGHT}Section 1/8: Account configuration")
    duo_data["account_info"] = get_and_save("account info", "get_info_summary")
    
    # 2. Users
    print(f"  {Style.BRIGHT}Section 2/8: User information")
    duo_data["users"] = get_and_save("users", "get_users")
    
    # 3. Administrators
    print(f"  {Style.BRIGHT}Section 3/8: Administrator information")
    duo_data["admins"] = get_and_save("admins", "get_admins")
    
    # 4. Authentication devices
    print(f"  {Style.BRIGHT}Section 4/8: Device information")
    duo_data["phones"] = get_and_save("phones", "get_phones")
    duo_data["tokens"] = get_and_save("tokens", "get_tokens")
    
    # 5. Authentication logs (60 days)
    print(f"  {Style.BRIGHT}Section 5/8: Authentication logs")
    sixty_days_ago = int(time.time()) - (60 * 24 * 60 * 60)
    duo_data["auth_logs"] = get_and_save("auth logs", "get_authentication_log", mintime=sixty_days_ago)
    
    # 6. Admin logs
    print(f"  {Style.BRIGHT}Section 6/8: Administrative logs")
    duo_data["admin_logs"] = get_and_save("admin logs", "get_administrator_log")
    
    # 7. Policies and settings
    print(f"  {Style.BRIGHT}Section 7/10: Policy configuration")
    duo_data["settings"] = get_and_save("settings", "get_settings")
    duo_data["policies"] = get_and_save("policies", "get_policies_v2")
    
    # Try to get detailed policy information
    try:
        # Get the first policy to analyze in detail
        if duo_data["policies"] and len(duo_data["policies"]) > 0:
            policy_id = duo_data["policies"][0].get("policy_id", "")
            if policy_id:
                print(f"  - Retrieving detailed policy settings...")
                duo_data["policy_details"] = get_and_save("policy details", "get_policy_v2", policy_id)
    except Exception as e:
        print(f"    {Fore.YELLOW}Unable to retrieve detailed policy: {str(e)}")
        duo_data["policy_details"] = []
    
    # 8. Integrations and applications
    print(f"  {Style.BRIGHT}Section 8/10: Integrations and applications")
    duo_data["integrations"] = get_and_save("integrations", "get_integrations")
    duo_data["groups"] = get_and_save("groups", "get_groups")
    
    # 9. FIPS and security details
    print(f"  {Style.BRIGHT}Section 9/10: FIPS and security configuration")
    
    # FIPS status via API is not available; manual verification required
    print(f"  {Fore.YELLOW}⚠️ FIPS status endpoint not available via Admin API; please verify FIPS compliance manually (see Duo Federal Guide)")
    duo_data["fips_status"] = []
    
    # Trusted endpoints config via API is not available; manual verification required
    print(f"  {Fore.YELLOW}⚠️ Trusted endpoints API not available via Admin API; please verify configuration manually via Admin Console")
    duo_data["trusted_endpoints"] = []
    
    # 10. Session and authentication settings
    print(f"  {Style.BRIGHT}Section 10/10: Session and authentication settings")
    try:
        duo_data["telephony"] = get_and_save("telephony", "get_info_telephony_credits_used")
    except Exception as e:
        print(f"    {Fore.YELLOW}Telephony endpoint not available: {str(e)}")
        duo_data["telephony"] = []
    
    print(f"{Fore.GREEN}✅ All Duo data retrieval complete!")
    return duo_data

def analyze_auth_methods(auth_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze authentication methods used."""
    if not auth_logs or not isinstance(auth_logs, list):
        logger.warning("No authentication logs available for analysis")
        return {
            "total_auths": 0,
            "methods": [],
            "phishing_resistant_count": 0,
            "phishing_resistant_percentage": 0,
            "sms_phone_count": 0,
            "sms_phone_percentage": 0
        }
    
    # Count methods
    method_counts = {}
    for log in auth_logs:
        if not isinstance(log, dict):
            continue
        factor = safe_get(log, "factor", "unknown")
        method_counts[factor] = method_counts.get(factor, 0) + 1
    
    # Calculate totals and percentages
    total = len(auth_logs)
    methods = []
    
    # Phishing-resistant and SMS/Phone counts
    phishing_resistant = 0
    sms_phone = 0
    
    for method, count in sorted(method_counts.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total) * 100 if total > 0 else 0
        
        # Categorize methods
        is_phishing_resistant = False
        is_sms_phone = False
        
        if method in ["u2f", "webauthn", "hardware_token"]:
            is_phishing_resistant = True
            phishing_resistant += count
        elif method in ["sms", "phone"]:
            is_sms_phone = True
            sms_phone += count
        
        methods.append({
            "name": method,
            "count": count,
            "percentage": percentage,
            "is_phishing_resistant": is_phishing_resistant,
            "is_sms_phone": is_sms_phone
        })
    
    return {
        "total_auths": total,
        "methods": methods,
        "phishing_resistant_count": phishing_resistant,
        "phishing_resistant_percentage": (phishing_resistant / total) * 100 if total > 0 else 0,
        "sms_phone_count": sms_phone,
        "sms_phone_percentage": (sms_phone / total) * 100 if total > 0 else 0
    }

def analyze_users(users: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze user enrollment status."""
    if not users or not isinstance(users, list):
        logger.warning("No user data available for analysis")
        return {
            "total_users": 0,
            "unenrolled_users": [],
            "users_with_bypass": [],
            "users_with_hardware": [],
            "active_users": 0,
            "disabled_users": 0
        }
    
    total = len(users)
    
    # Users without MFA methods
    unenrolled = []
    for user in users:
        if not isinstance(user, dict):
            continue
        if (safe_get(user, "status") == "active" and 
            len(safe_get(user, "phones", [])) == 0 and 
            len(safe_get(user, "tokens", [])) == 0):
            unenrolled.append(user)
    
    # Users with bypass codes
    users_with_bypass = []
    for user in users:
        if not isinstance(user, dict):
            continue
        bypass_codes = safe_get(user, "bypass_codes", [])
        if isinstance(bypass_codes, list) and len(bypass_codes) > 0:
            users_with_bypass.append(user)
    
    # Users with hardware tokens
    users_with_hardware = []
    for user in users:
        if not isinstance(user, dict):
            continue
        tokens = safe_get(user, "tokens", [])
        if isinstance(tokens, list) and len(tokens) > 0:
            users_with_hardware.append(user)
    
    # Active/disabled users
    active_users = len([u for u in users if isinstance(u, dict) and safe_get(u, "status") == "active"])
    disabled_users = len([u for u in users if isinstance(u, dict) and safe_get(u, "status") == "disabled"])
    
    return {
        "total_users": total,
        "unenrolled_users": unenrolled,
        "users_with_bypass": users_with_bypass,
        "users_with_hardware": users_with_hardware,
        "active_users": active_users,
        "disabled_users": disabled_users
    }

def generate_cisa_report(auth_analysis: Dict[str, Any], output_dir: str) -> None:
    """Generate CISA compliance report."""
    report_file = f"{output_dir}/compliance_reports/cisa_compliance_report.txt"
    
    with open(report_file, "w") as f:
        f.write("CISA MFA COMPLIANCE ASSESSMENT\n")
        f.write("===============================\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("1. PHISHING-RESISTANT MFA USAGE\n")
        f.write("------------------------------\n")
        f.write("Phishing-resistant methods per CISA guidance include: WebAuthn/FIDO2, PIV/CAC, FIPS-validated hardware tokens\n\n")
        
        f.write("Authentication Methods in Use (last 60 days):\n")
        for method in auth_analysis["methods"]:
            status = ""
            if method["is_phishing_resistant"]:
                status = " ✅ Phishing-resistant"
                if method["name"] == "hardware_token":
                    status += " (if FIPS-validated)"
            elif method["is_sms_phone"]:
                status = " ⚠️ Not phishing-resistant, deprecated by CISA"
            elif method["name"] == "duo_push":
                status = " ⚠️ Not phishing-resistant"
            else:
                status = " ⚠️ Status unknown"
            
            f.write(f"- {method['name']}: {method['count']} authentications ({method['percentage']:.1f}%){status}\n")
        
        f.write("\n2. PRIVILEGED USER MFA REQUIREMENTS\n")
        f.write("--------------------------------\n")
        f.write("CISA Emergency Directive 22-02 requires privileged users to use phishing-resistant MFA.\n\n")
        
        f.write("Authentication Methods Summary:\n")
        f.write(f"- {auth_analysis['phishing_resistant_count']} of {auth_analysis['total_auths']} authentications used phishing-resistant methods ({auth_analysis['phishing_resistant_percentage']:.1f}%)\n\n")
        
        if auth_analysis["phishing_resistant_count"] > 0:
            f.write("✅ Some phishing-resistant authentication detected\n")
        else:
            f.write("⚠️ No phishing-resistant authentication detected - HIGH RISK\n")
        
        f.write("\nCISA COMPLIANCE SUMMARY\n")
        f.write("---------------------\n")
        
        if auth_analysis["phishing_resistant_count"] > 0:
            f.write("✅ PARTIAL COMPLIANCE: Phishing-resistant methods are in use\n")
        else:
            f.write("❌ NON-COMPLIANCE: No phishing-resistant methods detected\n")
            
        if auth_analysis["sms_phone_count"] > 0:
            f.write("⚠️ CISA WARNING: SMS/Phone authentication methods are in use and should be phased out\n")
        else:
            f.write("✅ CISA COMPLIANT: No SMS/Phone authentication methods detected\n")

def generate_nist_report(auth_analysis: Dict[str, Any], output_dir: str) -> None:
    """Generate NIST SP 800-63B compliance report."""
    report_file = f"{output_dir}/compliance_reports/nist_compliance_report.txt"
    
    with open(report_file, "w") as f:
        f.write("NIST SP 800-63B COMPLIANCE ASSESSMENT\n")
        f.write("====================================\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("NIST Authentication Assurance Levels (AAL):\n")
        f.write("- AAL1: Single-factor authentication (password)\n")
        f.write("- AAL2: Multi-factor authentication\n")
        f.write("- AAL3: Hardware-based MFA with phishing resistance\n\n")
        
        f.write("1. AUTHENTICATION METHODS ASSESSMENT\n")
        f.write("--------------------------------\n")
        
        # Count WebAuthn/FIDO2 methods
        fido_count = sum(m["count"] for m in auth_analysis["methods"] 
                        if m["name"] in ["u2f", "webauthn"])
        fido_pct = (fido_count / auth_analysis["total_auths"]) * 100 if auth_analysis["total_auths"] > 0 else 0
        
        # Count Hardware OTP tokens
        hardware_token_count = sum(m["count"] for m in auth_analysis["methods"]
                                  if m["name"] == "hardware_token")
        hardware_pct = (hardware_token_count / auth_analysis["total_auths"]) * 100 if auth_analysis["total_auths"] > 0 else 0
        
        # Count AAL2 methods (push, software OTP)
        aal2_methods_count = sum(m["count"] for m in auth_analysis["methods"]
                                if m["name"] in ["duo_push", "passcode"])
        aal2_pct = (aal2_methods_count / auth_analysis["total_auths"]) * 100 if auth_analysis["total_auths"] > 0 else 0
        
        # Count SMS/Phone
        sms_phone_pct = auth_analysis["sms_phone_percentage"]
        
        f.write(f"Hardware Security Keys (FIDO2/WebAuthn - AAL3 capable):\n")
        f.write(f"{fido_count} authentications ({fido_pct:.1f}%)\n\n")
        
        f.write(f"Hardware OTP Tokens (AAL3 if FIPS-validated):\n")
        f.write(f"{hardware_token_count} authentications ({hardware_pct:.1f}%)\n\n")
        
        f.write(f"Software OTP, Push, etc. (AAL2):\n")
        f.write(f"{aal2_methods_count} authentications ({aal2_pct:.1f}%)\n\n")
        
        f.write(f"SMS/Phone (AAL2, but deprecated):\n")
        f.write(f"{auth_analysis['sms_phone_count']} authentications ({sms_phone_pct:.1f}%)\n\n")
        
        f.write("2. NIST SP 800-63B COMPLIANCE ASSESSMENT\n")
        f.write("------------------------------------\n")
        
        f.write("Current Authentication Assurance Level:\n")
        if fido_count > 0 or hardware_token_count > 0:
            f.write("✅ AAL3 CAPABLE: Hardware-based authenticators in use\n")
        elif aal2_methods_count > 0 or auth_analysis["sms_phone_count"] > 0:
            f.write("✅ AAL2 CAPABLE: Multi-factor authentication in use\n")
        else:
            f.write("⚠️ AAL1 ONLY: No MFA methods detected or insufficient data\n")
        
        f.write("\nRecommendations for NIST Compliance:\n")
        if fido_count > 0:
            f.write("- Continue using FIDO2/WebAuthn security keys\n")
        else:
            f.write("- Implement FIDO2/WebAuthn security keys for highest assurance\n")
            
        if hardware_token_count > 0:
            f.write("- Ensure hardware tokens are FIPS 140-2/140-3 validated\n")
        else:
            f.write("- Consider adding FIPS-validated hardware tokens\n")
            
        if auth_analysis["sms_phone_count"] > 0:
            f.write("- Phase out SMS and phone call authentication methods\n")
            
        f.write("- Document authentication requirements in System Security Plan\n")

def _assess_fedramp_20x_signals(
    duo_data: Dict[str, Any],
    auth_analysis: Optional[Dict[str, Any]] = None,
    user_analysis: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Map Duo Admin API signals to official FedRAMP 2026 KSI-IAM indicators.

    Indicator IDs and outcome statements match FedRAMP/2026-markdown
    ``providers/20x/key-security-indicators/identity-and-access-management.md``.

    Status values are supporting evidence heuristics for agency/CSP assurance
    engineering—not a FedRAMP certification decision. Many KSIs require org-wide
    processes beyond Duo (especially JIT and SUS response automation).
    """
    admins = duo_data.get("admins", []) or []
    settings = duo_data.get("settings", {}) or {}
    integrations = duo_data.get("integrations", []) or []
    fips_status = duo_data.get("fips_status", {}) or {}
    trusted_endpoints = duo_data.get("trusted_endpoints", {}) or {}

    admin_roles = set()
    for admin in admins:
        if isinstance(admin, dict):
            role = safe_get(admin, "role", "")
            if role:
                admin_roles.add(role)
    has_separation = len(admin_roles) > 1
    admin_count = len(admins)

    global_policy = safe_get(settings, "global_policy", {})
    mfa_required = bool(safe_get(global_policy, "require_mfa", False)) if isinstance(global_policy, dict) else False

    phishing_resistant = False
    sms_phone_usage = False
    users_without_mfa = None
    if auth_analysis:
        phishing_resistant = auth_analysis.get("phishing_resistant_count", 0) > 0
        sms_phone_usage = auth_analysis.get("sms_phone_count", 0) > 0
    if user_analysis is not None:
        users_without_mfa = len(user_analysis.get("unenrolled_users", []) or [])

    auth_lifetime = safe_get(settings, "auth_lifetime", {})
    session_ok = None
    timeout_seconds = None
    if isinstance(auth_lifetime, dict):
        timeout_value = safe_get(auth_lifetime, "auth_lifetime", None)
        try:
            timeout_seconds = int(timeout_value) if timeout_value is not None else None
            if timeout_seconds is not None:
                session_ok = 0 < timeout_seconds <= 30 * 60
        except (ValueError, TypeError):
            session_ok = None

    fips_enabled = safe_get(fips_status, "fips_enabled", None) if isinstance(fips_status, dict) else None
    device_trust = safe_get(trusted_endpoints, "enabled", None) if isinstance(trusted_endpoints, dict) else None
    integration_count = len(integrations) if isinstance(integrations, list) else 0

    def outcome(ok: Optional[bool]) -> str:
        if ok is True:
            return "pass"
        if ok is False:
            return "fail"
        return "unknown"

    # KSI-IAM-APM: passwordless when feasible, else strong passwords + phishing-resistant MFA.
    # Duo cannot prove org-wide passwordless; proxy via phishing-resistant factors + MFA policy.
    apm_ok: Optional[bool] = None
    if auth_analysis is not None and user_analysis is not None:
        apm_ok = (
            mfa_required
            and users_without_mfa == 0
            and phishing_resistant
            and not sms_phone_usage
        )
    elif auth_analysis is not None:
        if not phishing_resistant or sms_phone_usage:
            apm_ok = False
        elif mfa_required:
            apm_ok = True
        else:
            apm_ok = False

    aam_ok = user_analysis is not None
    elp_ok = admin_count > 0 and has_separation
    jit_ok = None  # requires IdP/PAM evidence
    snu_ok = None  # inventory only — human attests integration hardening

    # KSI-IAM-SUS weak inputs from administrator logs (never auto-pass)
    admin_logs = duo_data.get("admin_logs", []) or []
    if isinstance(admin_logs, dict):
        for key in ("adminlogs", "administrator_log", "logs", "items"):
            if key in admin_logs and isinstance(admin_logs[key], list):
                admin_logs = admin_logs[key]
                break
        else:
            admin_logs = []
    sus_action_keywords = (
        "disable", "disabled", "delete", "deleted", "lock", "locked",
        "suspend", "suspended", "revoke", "revoked", "remove", "removed",
        "block", "blocked", "deactivate", "deactivated",
    )
    sus_signal_keywords = (
        "fail", "failed", "denied", "fraud", "suspicious", "anomaly",
        "brute", "lockout", "unauthorized", "risk",
    )
    disable_like_events = 0
    suspicious_signal_events = 0
    admin_log_sample_actions = []
    for entry in admin_logs if isinstance(admin_logs, list) else []:
        if not isinstance(entry, dict):
            continue
        blob = " ".join(
            str(entry.get(k, ""))
            for k in ("action", "description", "object", "message", "type", "activity")
        ).lower()
        if any(k in blob for k in sus_action_keywords):
            disable_like_events += 1
        if any(k in blob for k in sus_signal_keywords):
            suspicious_signal_events += 1
        act = entry.get("action") or entry.get("description") or entry.get("type")
        if act and len(admin_log_sample_actions) < 8:
            admin_log_sample_actions.append(str(act)[:120])

    admin_logs_count = len(admin_logs) if isinstance(admin_logs, list) else 0
    sus_evidence = {
        "admin_activity_logs_available_via_api": True,
        "admin_log_entries_collected": admin_logs_count,
        "disable_or_revoke_like_admin_actions_observed": disable_like_events,
        "suspicious_or_failure_signal_strings_in_admin_logs": suspicious_signal_events,
        "sample_admin_actions": admin_log_sample_actions,
        "automated_disable_on_suspicious_activity_not_verified": True,
        "weak_input_only": True,
    }
    sus_ok = None  # never pass on logs alone

    catalog = {row[0]: (row[1], row[2]) for row in FEDRAMP_2026_KSI_IAM}

    ksi_results = {
        "KSI-IAM-AAM": {
            "title": catalog["KSI-IAM-AAM"][0],
            "official_outcome": catalog["KSI-IAM-AAM"][1],
            "status": outcome(aam_ok),
            "evidence": {
                "admin_api_admins_exported": admin_count,
                "user_enrollment_export_available": user_analysis is not None,
                "supports_scheduled_regeneration": True,
            },
            "notes": (
                "Official KSI (2026-markdown): lifecycle/privileges of accounts, roles, and groups managed "
                "using automation. This tool only evidences whether Duo Admin API exports can feed automated "
                "collection; complete AAM with HR/IdP provisioning and scheduled runs."
            ),
            "source": FEDRAMP_2026_MARKDOWN_IAM,
        },
        "KSI-IAM-APM": {
            "title": catalog["KSI-IAM-APM"][0],
            "official_outcome": catalog["KSI-IAM-APM"][1],
            "status": outcome(apm_ok),
            "evidence": {
                "mfa_required_policy": mfa_required,
                "phishing_resistant_methods_observed": phishing_resistant,
                "sms_or_phone_methods_observed": sms_phone_usage,
                "users_without_mfa": users_without_mfa,
            },
            "notes": (
                "Official KSI (2026-markdown): passwordless when feasible, otherwise strong passwords with "
                "phishing-resistant MFA. There is no KSI-IAM-MFA ID in Consolidated Rules 2026; phishing-resistant "
                "MFA is part of APM. Duo proxy: FIDO2/WebAuthn/PIV signals, MFA required, SMS/voice not in use."
            ),
            "source": FEDRAMP_2026_MARKDOWN_IAM,
        },
        "KSI-IAM-ELP": {
            "title": catalog["KSI-IAM-ELP"][0],
            "official_outcome": catalog["KSI-IAM-ELP"][1],
            "status": outcome(elp_ok),
            "evidence": {
                "admin_count": admin_count,
                "distinct_admin_roles": sorted(admin_roles),
                "role_separation": has_separation,
                "session_timeout_seconds": timeout_seconds,
                "session_timeout_within_30m_heuristic": session_ok,
            },
            "notes": (
                "Official KSI: persistently ensure users/devices only access needed resources. Duo-visible slice: "
                "admin role separation and privileged admin count. Session lifetime is supporting evidence "
                "(related controls include AC-12), not a substitute for org-wide least privilege."
            ),
            "source": FEDRAMP_2026_MARKDOWN_IAM,
        },
        "KSI-IAM-JIT": {
            "title": catalog["KSI-IAM-JIT"][0],
            "official_outcome": catalog["KSI-IAM-JIT"][1],
            "status": outcome(jit_ok),
            "evidence": {
                "duo_admin_roles_observed": sorted(admin_roles),
                "jit_model_not_exposed_by_duo_admin_api": True,
            },
            "notes": (
                "Official KSI: least-privileged, role/attribute-based, just-in-time authorization, persistently "
                "reviewed. Document JIT in IdP/PAM/Security Decision Record; Duo Admin API cannot fully prove JIT."
            ),
            "source": FEDRAMP_2026_MARKDOWN_IAM,
        },
        "KSI-IAM-SNU": {
            "title": catalog["KSI-IAM-SNU"][0],
            "official_outcome": catalog["KSI-IAM-SNU"][1],
            "status": outcome(snu_ok),
            "evidence": {
                "integration_count": integration_count,
                "admin_api_used_for_this_assessment": True,
            },
            "notes": (
                "Official KSI: secure authentication for non-user accounts and services, persistently reviewed. "
                "Inventory integrations and attest key rotation / machine auth; inventory alone is not a pass."
            ),
            "source": FEDRAMP_2026_MARKDOWN_IAM,
        },
        "KSI-IAM-SUS": {
            "title": catalog["KSI-IAM-SUS"][0],
            "official_outcome": catalog["KSI-IAM-SUS"][1],
            "status": outcome(sus_ok),
            "evidence": sus_evidence,
            "notes": (
                "Official KSI: privileged accounts disabled or secured in response to suspicious activity "
                "(not merely session timeout). Admin API logs are weak inputs only (visibility / disable-like "
                "actions); they do NOT prove automated response. Status stays unknown without SOAR/IdP attestation."
            ),
            "source": FEDRAMP_2026_MARKDOWN_IAM,
        },
    }

    pinned_iam = FEDRAMP_2026_MARKDOWN_PIN.get("iam_blob_url", FEDRAMP_2026_MARKDOWN_IAM)
    for _kid, _meta in ksi_results.items():
        _meta["source"] = pinned_iam
        _meta["ruleset_commit_sha"] = FEDRAMP_2026_MARKDOWN_PIN.get("commit_sha")

    legacy = {
        "admin_count_reasonable": admin_count <= 5,
        "admin_role_separation": has_separation,
        "fips_enabled": fips_enabled,
        "device_trust_enabled": device_trust,
        "session_timeout_ok": session_ok,
        "duo_federal_manual_check_required": True,
    }

    return {
        "framework": "FedRAMP Consolidated Rules for 2026 (20x KSI-IAM) — FedRAMP/2026-markdown",
        "ruleset_note": (
            "Indicator IDs and outcome quotes are from the FedRAMP 2026 markdown corpus "
            "(Consolidated Rules launch noted 2026-06-24 in that source). Phase One pilot materials and "
            "RFC-0006 are historical and are not the primary indicator list."
        ),
        "ruleset_provenance": dict(FEDRAMP_2026_MARKDOWN_PIN),
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tool_version": SCRIPT_VERSION,
        "ksi_results": ksi_results,
        "legacy_signals": legacy,
        "references": [
            FEDRAMP_2026_MARKDOWN_REPO,
            FEDRAMP_2026_MARKDOWN_PIN.get("iam_blob_url", FEDRAMP_2026_MARKDOWN_IAM),
            FEDRAMP_2026_MARKDOWN_PIN.get("tree_url", FEDRAMP_2026_MARKDOWN_KSI_INDEX),
            "https://github.com/FedRAMP/2026-markdown/blob/main/reference/key-security-indicators.md",
            "https://duo.com/docs/duo-federal-guide",
        ],
    }




def generate_ksi_security_decision_record_stubs(
    duo_data: Dict[str, Any],
    output_dir: str,
    auth_analysis: Optional[Dict[str, Any]] = None,
    user_analysis: Optional[Dict[str, Any]] = None,
) -> str:
    """Write Security Decision Record (SDR) markdown stubs per official KSI-IAM.

    FedRAMP 2026 KSI guidance expects outcome-oriented documentation (how activities
    are performed, measured, and evidenced). Stubs pre-fill Duo-derived fields and
    leave attestation blanks for assurance engineering.
    """
    assessment = _assess_fedramp_20x_signals(duo_data, auth_analysis, user_analysis)
    sdr_dir = os.path.join(output_dir, "compliance_reports", "security_decision_records")
    os.makedirs(sdr_dir, exist_ok=True)
    pin = assessment.get("ruleset_provenance") or dict(FEDRAMP_2026_MARKDOWN_PIN)
    sha = pin.get("commit_sha", "")
    index_lines = [
        "# Security Decision Records — KSI-IAM (Duo-supporting)",
        "",
        f"Generated: {assessment.get('generated_at')}",
        f"Tool version: {assessment.get('tool_version')}",
        f"Ruleset commit: `{sha}` ({pin.get('commit_date_utc')})",
        f"Ruleset tree: {pin.get('tree_url')}",
        "",
        "Complete blanks with assurance engineering. FedRAMP/2026-markdown is the indicator source.",
        "",
        "| KSI | Status (tool heuristic) | SDR |",
        "|-----|-------------------------|-----|",
    ]

    for ksi_id, meta in assessment.get("ksi_results", {}).items():
        status = meta.get("status", "unknown")
        title = meta.get("title", ksi_id)
        outcome_text = meta.get("official_outcome", "")
        notes = meta.get("notes", "")
        evidence = meta.get("evidence") or {}
        fname = f"{ksi_id}.md"
        fpath = os.path.join(sdr_dir, fname)
        evidence_md = "\n".join(f"- `{k}`: `{v}`" for k, v in evidence.items())
        body = f"""# Security Decision Record — {ksi_id}

## Indicator
- **ID:** {ksi_id}
- **Title:** {title}
- **Official outcome (FedRAMP/2026-markdown @{sha[:12]}):**
  > {outcome_text}
- **Source blob:** {pin.get('iam_blob_url')}

## Tool heuristic (not certification)
- **Status from duo-audit:** `{status}`
- **Assessment notes:** {notes}

## Pre-filled Duo evidence (from this run)
{evidence_md or '_None collected._'}

## Assurance prompts (complete for 2026 KSI program)
1. **How** are the activities that produce this outcome performed (people, systems, automation)?
2. **Where** in the tech or policy stack do they exist (Duo, IdP, PAM, HRIS, SOAR, etc.)?
3. **What** is measured or reported today related to these activities? Desired metrics?
4. **Why** gaps exist if activities or metrics are missing?
5. **When** do activities and measurements occur (cadence)?
6. **Where** are monitoring data sources (APIs, SIEM, tickets)?

## Attestations (owner / date)
- [ ] Outcome implemented for in-scope populations: _______________ (owner) ________ (date)
- [ ] Evidence regenerable on demand / schedule: _______________
- [ ] Customer-facing metrics for agency assurance package: _______________

## Linked artifacts from this assessment
- `../fedramp_20x_ksi_evidence.json`
- `../fedramp_compliance_report.txt`

## Residual risk / exceptions
_Document deviations, compensating controls, and inheritance from Duo Federal authorization._
"""
        with open(fpath, "w") as fh:
            fh.write(body)
        index_lines.append(f"| `{ksi_id}` | `{status}` | [{fname}](./{fname}) |")

    index_path = os.path.join(sdr_dir, "README.md")
    with open(index_path, "w") as fh:
        fh.write("\n".join(index_lines) + "\n")
    return sdr_dir


def generate_fedramp_20x_ksi_json(
    duo_data: Dict[str, Any],
    output_dir: str,
    auth_analysis: Optional[Dict[str, Any]] = None,
    user_analysis: Optional[Dict[str, Any]] = None,
) -> str:
    """Write machine-readable FedRAMP 20x KSI evidence package (JSON)."""
    assessment = _assess_fedramp_20x_signals(duo_data, auth_analysis, user_analysis)
    path = f"{output_dir}/compliance_reports/fedramp_20x_ksi_evidence.json"
    with open(path, "w") as f:
        json.dump(assessment, f, indent=2, default=str)
    return path


def generate_fedramp_report(
    duo_data: Dict[str, Any],
    output_dir: str,
    auth_analysis: Optional[Dict[str, Any]] = None,
    user_analysis: Optional[Dict[str, Any]] = None,
) -> None:
    """Generate FedRAMP 20x–aligned human-readable compliance report (plus legacy themes)."""
    report_file = f"{output_dir}/compliance_reports/fedramp_compliance_report.txt"
    assessment = _assess_fedramp_20x_signals(duo_data, auth_analysis, user_analysis)
    admins = duo_data.get("admins", []) or []
    settings = duo_data.get("settings", {}) or {}
    fips_status = duo_data.get("fips_status", {}) or {}
    trusted_endpoints = duo_data.get("trusted_endpoints", {}) or {}
    legacy = assessment["legacy_signals"]
    ksi_results = assessment["ksi_results"]

    with open(report_file, "w") as f:
        f.write("FEDRAMP 20x + LEGACY FEDRAMP COMPLIANCE ASSESSMENT\n")
        f.write("==================================================\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Tool version: {SCRIPT_VERSION}\n")
        f.write("Scope: Duo Security as an identity / MFA control plane for FedRAMP-authorized systems\n\n")

        f.write("CONTEXT: FEDRAMP CONSOLIDATED RULES FOR 2026 (20x KSIs)\n")
        f.write("------------------------------------------------------\n")
        f.write("Primary source: https://github.com/FedRAMP/2026-markdown\n")
        f.write("(providers/20x/key-security-indicators/identity-and-access-management.md).\n")
        f.write("KSIs measure outcomes continuously; not a classic control-by-control narrative alone.\n")
        f.write("Maps Duo signals to six official KSI-IAM IDs (AAM, APM, ELP, JIT, SNU, SUS).\n")
        f.write("Phishing-resistant MFA is under KSI-IAM-APM (no KSI-IAM-MFA ID in 2026-markdown).\n")
        f.write("Machine-readable twin: compliance_reports/fedramp_20x_ksi_evidence.json\n\n")
        f.write("Official references:\n")
        for ref in assessment["references"]:
            f.write(f"  - {ref}\n")
        f.write("\n")

        f.write("1. FEDRAMP 2026 KEY SECURITY INDICATORS (KSI-IAM — OFFICIAL IDs)\n")
        f.write("--------------------------------------------------------------\n")
        for ksi_id, meta in ksi_results.items():
            status = meta.get("status", "unknown").upper()
            f.write(f"{ksi_id}: {meta.get('title')}\n")
            if meta.get("official_outcome"):
                f.write(f"  Official outcome: {meta.get('official_outcome')}\n")
            f.write(f"  Status: {status}\n")
            f.write(f"  Notes: {meta.get('notes', '')}\n")
            ev = meta.get("evidence") or {}
            for k, v in ev.items():
                f.write(f"  Evidence.{k}: {v}\n")
            f.write("\n")

        pass_count = sum(1 for m in ksi_results.values() if m.get("status") == "pass")
        fail_count = sum(1 for m in ksi_results.values() if m.get("status") == "fail")
        unk_count = sum(1 for m in ksi_results.values() if m.get("status") == "unknown")
        f.write(f"KSI rollup (this scan): pass={pass_count} fail={fail_count} unknown={unk_count}\n\n")

        f.write("2. ADMINISTRATOR ACCESS CONTROLS (KSI-IAM-ELP / AC-2 / AC-6 themes)\n")
        f.write("------------------------------------------------------------------\n")
        admin_count = len(admins)
        f.write(f"Administrator Count: {admin_count}\n\n")
        f.write("Administrator Details:\n")
        for admin in sorted(admins, key=lambda x: safe_get(x, "name", "")):
            name = safe_get(admin, "name", "Unknown")
            email = safe_get(admin, "email", "No email")
            role = safe_get(admin, "role", "Unknown")
            status = safe_get(admin, "status", "Unknown")
            email_verified = safe_get(admin, "email_verified", False)
            f.write(f"- {name} ({email})\n")
            f.write(f"  • Role: {role}\n")
            f.write(f"  • Status: {status}\n")
            f.write(f"  • Email verified / 2FA signal: {'Yes' if email_verified else 'No'}\n")

        f.write("\nAssessment:\n")
        f.write(
            f"✓ Prefer few highly privileged admins: "
            f"{'YES' if legacy.get('admin_count_reasonable') else f'REVIEW (count={admin_count}; target often <=5 Owners/Admins)'}\n"
        )
        f.write(
            f"✓ Distinct admin roles (separation of duties signal): "
            f"{'YES' if legacy.get('admin_role_separation') else 'NO (all admins appear to share one role)'}\n\n"
        )

        f.write("3. CONTINUOUS MONITORING / AUDIT EVIDENCE (20x persistence)\n")
        f.write("----------------------------------------------------------\n")
        f.write("20x expects KSIs to be validated repeatedly (machine checks on a short cadence for\n")
        f.write("automatable indicators; process checks on a longer cadence). For Duo:\n")
        f.write("- Authentication logs: Admin API (export and retain per agency policy)\n")
        f.write("- Administrator activity logs: Admin API\n")
        f.write("- Re-run duo-audit.py on a schedule; keep fedramp_20x_ksi_evidence.json as evidence artifacts\n")
        f.write("- Align retention with agency / authorizing official requirements (legacy packages often\n")
        f.write("  cited multi-tier online/archive retention; confirm against your ATO boundary)\n\n")

        f.write("4. SESSION MANAGEMENT (supports ELP / AC-12 — not KSI-IAM-SUS)\n")
        f.write("--------------------------------------------------\n")
        auth_lifetime = safe_get(settings, "auth_lifetime", {})
        if auth_lifetime and isinstance(auth_lifetime, dict):
            timeout_value = safe_get(auth_lifetime, "auth_lifetime", "Unknown")
            timeout_enabled = safe_get(auth_lifetime, "auth_lifetime_enabled", "Unknown")
            f.write(f"Authentication session timeout: {timeout_value} seconds\n")
            f.write(f"Session expiration enforced: {timeout_enabled}\n")
            if legacy.get("session_timeout_ok") is True:
                f.write("✓ Session timeout within common 30-minute federal benchmark: YES\n\n")
            elif legacy.get("session_timeout_ok") is False:
                f.write("✓ Session timeout within common 30-minute federal benchmark: NO — tighten policy\n\n")
            else:
                f.write("✓ Session timeout assessment: Unable to determine from API payload\n\n")
        else:
            f.write("Session timeout settings: Not available via this collection path\n\n")

        f.write("5. CRYPTOGRAPHIC MODULE / FIPS (service offering + on-prem components)\n")
        f.write("---------------------------------------------------------------------\n")
        if isinstance(fips_status, dict) and fips_status:
            fips_enabled = safe_get(fips_status, "fips_enabled", False)
            f.write(f"FIPS mode signal from API: {'Yes' if fips_enabled else 'No'}\n")
            if fips_enabled:
                f.write("✅ FIPS enablement signal present (confirm FIPS 140-2/140-3 module coverage for boundary)\n\n")
            else:
                f.write("❌ FIPS enablement not confirmed via API — required for Duo Federal / many ATO paths\n\n")
        else:
            f.write("FIPS status: Not exposed by Duo Admin API client in this environment\n")
            f.write("⚠️ Manually verify Duo Federal edition and FIPS-validated components (Auth Proxy, etc.)\n")
            f.write("   https://duo.com/docs/duo-federal-guide\n\n")

        f.write("6. DEVICE TRUST / TRUSTED ENDPOINTS\n")
        f.write("----------------------------------\n")
        if isinstance(trusted_endpoints, dict) and trusted_endpoints:
            enabled = safe_get(trusted_endpoints, "enabled", False)
            f.write(f"Device trust policies enabled: {'Yes' if enabled else 'No'}\n")
            f.write(("✅ " if enabled else "⚠️ ") + "Device posture assessment signal\n\n")
        else:
            f.write("Device trust policies: Not available via API — verify in Admin Console\n\n")

        f.write("7. AUTHORIZATION PATH (20x PILOT VS TRADITIONAL PACKAGE)\n")
        f.write("--------------------------------------------------------\n")
        f.write("Duo as a commercial SaaS IdP/MFA service is typically authorized as Duo Federal\n")
        f.write("(FedRAMP Marketplace authorization) while agencies inherit controls into their systems.\n")
        f.write("For FedRAMP 20x pilots and continuous monitoring programs:\n")
        f.write("- Prefer automated evidence (this tool's JSON + scheduled runs)\n")
        f.write("- Document inheritance from Duo's authorization vs customer-responsible configuration\n")
        f.write("- Confirm phishing-resistant MFA policy at the agency IdP and application tiers\n")
        f.write("- Use Duo Federal with FIPS-validated crypto where required by impact level\n\n")

        f.write("OVERALL ASSESSMENT (HEURISTIC — NOT AN ATO DECISION)\n")
        f.write("----------------------------------------------------\n")
        if fail_count == 0 and pass_count >= 3:
            f.write("✅ STRONG 20x IAM SIGNALS: Core KSI-IAM outcomes look favorable; close 'unknown' items\n")
        elif fail_count == 0:
            f.write("⚠️ INCOMPLETE EVIDENCE: Increase API coverage (auth methods, users) and re-run\n")
        elif fail_count <= 2:
            f.write("⚠️ GAPS: Remediate failed KSI-IAM items (especially MFA / phishing resistance)\n")
        else:
            f.write("❌ MULTIPLE KSI-IAM FAILURES: Prioritize MFA enforcement and authenticator modernization\n")
        f.write("\nManual verification still required for Duo Federal subscription and FIPS module inventory.\n")
        f.write("Machine-readable twin: fedramp_20x_ksi_evidence.json\n")

def generate_user_report(user_analysis: Dict[str, Any], output_dir: str) -> None:
    """Generate user enrollment status report."""
    report_file = f"{output_dir}/compliance_reports/user_enrollment_report.txt"
    
    with open(report_file, "w") as f:
        f.write("USER ENROLLMENT STATUS REPORT\n")
        f.write("==========================\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        total_users = user_analysis["total_users"]
        f.write(f"Total Users: {total_users}\n\n")
        
        f.write("Enrollment Statistics:\n")
        f.write("---------------------\n")
        
        # Users without MFA
        unenrolled_count = len(user_analysis["unenrolled_users"])
        unenrolled_pct = (unenrolled_count / total_users) * 100 if total_users > 0 else 0
        f.write(f"- Users without any authentication devices: {unenrolled_count} ({unenrolled_pct:.1f}%)\n")
        
        # Users with bypass codes
        bypass_count = len(user_analysis["users_with_bypass"])
        bypass_pct = (bypass_count / total_users) * 100 if total_users > 0 else 0
        f.write(f"- Users with bypass codes: {bypass_count} ({bypass_pct:.1f}%)\n\n")
        
        # Users with hardware tokens
        hardware_count = len(user_analysis["users_with_hardware"])
        hardware_pct = (hardware_count / total_users) * 100 if total_users > 0 else 0
        f.write(f"- Users with hardware tokens: {hardware_count} ({hardware_pct:.1f}%)\n\n")
        
        f.write("User Status:\n")
        f.write("-----------\n")
        
        active_pct = (user_analysis["active_users"] / total_users) * 100 if total_users > 0 else 0
        disabled_pct = (user_analysis["disabled_users"] / total_users) * 100 if total_users > 0 else 0
        
        f.write(f"- Active users: {user_analysis['active_users']} ({active_pct:.1f}%)\n")
        f.write(f"- Disabled users: {user_analysis['disabled_users']} ({disabled_pct:.1f}%)\n\n")
        
        f.write("High-Risk Users (need remediation):\n")
        f.write("---------------------------------\n")
        
        # List up to 10 unenrolled active users
        for user in user_analysis["unenrolled_users"][:10]:
            username = safe_get(user, 'username', 'Unknown')
            email = safe_get(user, 'email', 'No email')
            f.write(f"- {username} ({email})\n")
        
        if len(user_analysis["unenrolled_users"]) > 10:
            f.write(f"\n...and {len(user_analysis['unenrolled_users']) - 10} more\n")
        
        f.write("\nCOMPLIANCE ASSESSMENT:\n")
        f.write("---------------------\n")
        
        if unenrolled_count == 0:
            f.write("✅ COMPLIANT: All active users have MFA methods enrolled\n")
        else:
            f.write(f"❌ NON-COMPLIANT: {unenrolled_count} active users do not have MFA methods enrolled\n")
        
        if bypass_count == 0:
            f.write("✅ COMPLIANT: No users have bypass codes\n")
        else:
            f.write(f"⚠️ POTENTIAL RISK: {bypass_count} users have bypass codes which may circumvent MFA\n")

def generate_policy_report(settings: Dict[str, Any], output_dir: str) -> None:
    """Generate authentication policy assessment report."""
    report_file = f"{output_dir}/compliance_reports/policy_assessment_report.txt"
    
    with open(report_file, "w") as f:
        f.write("AUTHENTICATION POLICY ASSESSMENT\n")
        f.write("==============================\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("Global Policy Settings:\n")
        f.write("---------------------\n")
        
        # Extract global policy settings if available
        global_policy = safe_get(settings, "global_policy", {})
        
        if global_policy and isinstance(global_policy, dict):
            require_mfa = safe_get(global_policy, 'require_mfa', False)
            fido2_enforced = safe_get(global_policy, 'fido2_enforced', False)
            hardware_required = safe_get(global_policy, 'hardware_token_required', False)
            duo_push_setting = safe_get(global_policy, 'duo_push_setting', 'unknown')
            sms_setting = safe_get(global_policy, 'sms_setting', 'unknown')
            voice_setting = safe_get(global_policy, 'voice_setting', 'unknown')
            
            f.write(f"- MFA Required: {require_mfa}\n")
            f.write(f"- FIDO2 Enforced: {fido2_enforced}\n")
            f.write(f"- Hardware Token Required: {hardware_required}\n")
            f.write(f"- Duo Push Setting: {duo_push_setting}\n")
            f.write(f"- SMS/Phone Setting: {sms_setting}/{voice_setting}\n\n")
        else:
            f.write("No global policy found\n\n")
        
        f.write("COMPLIANCE ASSESSMENT:\n")
        f.write("---------------------\n")
        
        if global_policy and isinstance(global_policy, dict):
            require_mfa = safe_get(global_policy, 'require_mfa', False)
            fido2_enforced = safe_get(global_policy, 'fido2_enforced', False)
            hardware_required = safe_get(global_policy, 'hardware_token_required', False)
            sms_allowed = safe_get(global_policy, 'sms_setting', '') == 'allowed'
            voice_allowed = safe_get(global_policy, 'voice_setting', '') == 'allowed'
            
            f.write(f"{'✅ MFA is globally required' if require_mfa else '❌ MFA is NOT globally required'}\n")
            f.write(f"{'✅ FIDO2 (phishing-resistant) is enforced' if fido2_enforced else '⚠️ FIDO2 (phishing-resistant) is NOT enforced'}\n")
            f.write(f"{'✅ Hardware tokens are required' if hardware_required else '⚠️ Hardware tokens are NOT required'}\n")
            
            if sms_allowed or voice_allowed:
                f.write("⚠️ SMS/Phone authentication is allowed (CISA recommends phasing out)\n")
            else:
                f.write("✅ SMS/Phone authentication is disabled\n")
        else:
            f.write("❌ NO GLOBAL POLICY: Unable to assess compliance without policy information\n")
        
        f.write("\nRECOMMENDATIONS:\n")
        f.write("---------------\n")
        
        if global_policy and isinstance(global_policy, dict):
            if not safe_get(global_policy, 'require_mfa', False):
                f.write("- Enable global MFA requirement\n")
            if not safe_get(global_policy, 'fido2_enforced', False):
                f.write("- Enable FIDO2 enforcement for phishing-resistant authentication\n")
            if not safe_get(global_policy, 'hardware_token_required', False):
                f.write("- Consider requiring hardware tokens for sensitive users\n")
            if safe_get(global_policy, 'sms_setting', '') == 'allowed' or safe_get(global_policy, 'voice_setting', '') == 'allowed':
                f.write("- Phase out SMS/Phone authentication methods per CISA guidance\n")
        else:
            f.write("- Configure a global policy to enforce MFA requirements\n")
            f.write("- Prioritize phishing-resistant methods (FIDO2, hardware tokens)\n")
            f.write("- Disable SMS/Phone authentication\n")

def generate_executive_summary(
    auth_analysis: Dict[str, Any],
    user_analysis: Dict[str, Any],
    settings: Dict[str, Any],
    output_dir: str
) -> None:
    """Generate executive summary report."""
    report_file = f"{output_dir}/compliance_reports/executive_summary.txt"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    with open(report_file, "w") as f:
        f.write("DUO SECURITY COMPLIANCE ASSESSMENT\n")
        f.write("==================================\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Assessment ID: duo-compliance-{timestamp}\n")
        f.write(f"Script Version: {SCRIPT_VERSION}\n\n")
        
        f.write("EXECUTIVE SUMMARY\n")
        f.write("----------------\n")
        f.write("This assessment evaluates your Duo Security configuration against:\n")
        f.write("1. FedRAMP 20x Key Security Indicators (KSI-IAM themes) + legacy FedRAMP control themes\n")
        f.write("2. NIST SP 800-63B authentication standards\n")
        f.write("3. CISA Emergency Directive 22-02 / phishing-resistant MFA expectations\n\n")
        
        f.write("KEY FINDINGS\n")
        f.write("-----------\n")
        
        # Extract key policy settings
        global_policy = safe_get(settings, "global_policy", {})
        mfa_required = safe_get(global_policy, "require_mfa", False) if isinstance(global_policy, dict) else False
        
        # Get phishing-resistant and SMS/phone usage
        phishing_resistant = auth_analysis["phishing_resistant_count"] > 0
        sms_phone_usage = auth_analysis["sms_phone_count"] > 0
        
        # Get users without MFA
        users_without_mfa = len(user_analysis["unenrolled_users"])
        
        f.write(f"1. MFA Enforcement: {'Enabled ✅' if mfa_required else 'Not enabled ❌'}\n")
        f.write(f"2. Phishing-Resistant Methods: {'In use ✅' if phishing_resistant else 'Not detected ❌'}\n")
        f.write(f"3. SMS/Phone Authentication: {'In use ⚠️' if sms_phone_usage else 'Not in use ✅'}\n")
        f.write(f"4. Users Without MFA: {users_without_mfa} {'✅' if users_without_mfa == 0 else '❌'}\n\n")
        
        f.write("COMPLIANCE STATUS\n")
        f.write("---------------\n")
        
        # CISA compliance
        cisa_compliant = phishing_resistant and not sms_phone_usage
        
        # NIST compliance
        nist_aal = "AAL1 ONLY ❌"
        if auth_analysis["total_auths"] > 0:
            if phishing_resistant:
                nist_aal = "AAL2 CAPABLE ✅ (AAL3 CAPABLE with FIPS validation)"
            else:
                nist_aal = "AAL2 CAPABLE ✅"
        
        # FedRAMP 2026 KSI-IAM-APM heuristic
        fedramp_apm = mfa_required and users_without_mfa == 0 and phishing_resistant and not sms_phone_usage
        fedramp_legacy = mfa_required and users_without_mfa == 0
        
        f.write(f"CISA Directive 22-02: {'COMPLIANT ✅' if cisa_compliant else 'NON-COMPLIANT ❌'}\n")
        f.write(f"NIST SP 800-63B: {nist_aal}\n")
        f.write(f"FedRAMP 2026 KSI-IAM-APM (Duo heuristic): {'FAVORABLE ✅' if fedramp_apm else 'GAPS ❌'}\n")
        f.write(f"Legacy FedRAMP MFA baseline: {'BASELINE ✅' if fedramp_legacy else 'NON-COMPLIANT ❌'}\n\n")
        
        f.write("PRIORITY RECOMMENDATIONS\n")
        f.write("----------------------\n")
        f.write("1. Enforce MFA for all users (policy + enrollment)\n")
        f.write("2. Prefer phishing-resistant / passwordless authenticators (FIDO2/WebAuthn, PIV/CAC)\n")
        f.write("3. Phase out SMS and phone call authentication (KSI-IAM-APM / CISA)\n")
        f.write("4. Limit Duo Owner/Admin roles; use scoped roles (KSI-IAM-ELP)\n")
        f.write("5. Schedule continuous re-validation; retain fedramp_20x_ksi_evidence.json\n")
        f.write("6. Confirm Duo Federal + FIPS 140-2/140-3 module coverage for the ATO boundary\n\n")
        
        f.write("NEXT STEPS\n")
        f.write("---------\n")
        f.write("1. Review fedramp_compliance_report.txt and fedramp_20x_ksi_evidence.json\n")
        f.write("2. Remediate failed KSI-IAM signals (especially phishing-resistant MFA)\n")
        f.write("3. Wire this scan into CI or a recurring job for 20x-style persistence\n")
        f.write("4. Verify Duo Federal edition and inheritance in your authorization package\n\n")
        
        f.write("Tool: https://ethantroy.dev — contact your security team for ATO decisions.")

def generate_compliance_checklist(output_dir: str) -> None:
    """Generate compliance checklist."""
    report_file = f"{output_dir}/compliance_reports/compliance_checklist.txt"
    
    with open(report_file, "w") as f:
        f.write("DUO SECURITY COMPLIANCE CHECKLIST\n")
        f.write("================================\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("FEDRAMP 2026 KSI-IAM (OFFICIAL IDs — FedRAMP/2026-markdown)\n")
        f.write("------------------------------------------------------------\n")
        f.write("[ ] KSI-IAM-AAM: Automating Account Management\n")
        f.write("    - Account/role/group lifecycle privileges managed with automation\n\n")
        f.write("[ ] KSI-IAM-APM: Adopting Passwordless Methods\n")
        f.write("    - Passwordless when feasible; else strong passwords + phishing-resistant MFA\n")
        f.write("    - No separate KSI-IAM-MFA ID in Consolidated Rules 2026\n\n")
        f.write("[ ] KSI-IAM-ELP: Ensuring Least Privilege\n")
        f.write("    - Persistently ensure users/devices only access needed resources\n\n")
        f.write("[ ] KSI-IAM-JIT: Authorizing Just-in-Time\n")
        f.write("    - Role/attribute-based JIT for user and non-user accounts (IdP/PAM)\n\n")
        f.write("[ ] KSI-IAM-SNU: Securing Non-User Authentication\n")
        f.write("    - Secure auth for integrations/services; keys rotated\n\n")
        f.write("[ ] KSI-IAM-SUS: Responding to Suspicious Activity\n")
        f.write("    - Privileged accounts disabled/secured when suspicious activity is detected\n\n")
        f.write("Source: https://github.com/FedRAMP/2026-markdown/blob/main/providers/20x/key-security-indicators/identity-and-access-management.md\n\n")

        f.write("LEGACY FEDRAMP / SP 800-53 REV 5 CONTROL THEMES (STILL USEFUL)\n")
        f.write("------------------------------------------------------------\n")
        f.write("[ ] AC-2: Account Management\n")
        f.write("    - Limited administrator accounts with proper role separation\n")
        f.write("    - Clear user provisioning/deprovisioning procedures\n")
        f.write("    - Regular account reviews and audit\n\n")
        
        f.write("[ ] AC-12: Session Termination\n")
        f.write("    - Verify session timeout settings\n")
        f.write("    - Ensure inactive sessions are terminated automatically\n\n")
        
        f.write("[ ] IA-2: Identification and Authentication\n")
        f.write("    - MFA enforcement for all users\n")
        f.write("    - Privileged accounts use hardware-based authentication\n")
        f.write("    - FIPS 140-2/140-3 validated cryptographic modules\n\n")
        
        f.write("[ ] IA-5: Authenticator Management\n")
        f.write("    - Secure handling of authentication secrets\n")
        f.write("    - Password policies aligned with NIST guidelines\n")
        f.write("    - Hardware token management procedures\n\n")
        
        f.write("[ ] AU-2: Audit Events\n")
        f.write("    - Authentication activity logging\n")
        f.write("    - Administrator actions logging\n")
        f.write("    - 90-day minimum log retention\n\n")
        
        f.write("[ ] SC-8: Transmission Confidentiality\n")
        f.write("    - Ensure encrypted communication\n")
        f.write("    - TLS 1.2+ for all connections\n\n")
        
        f.write("NIST SP 800-63B REQUIREMENTS\n")
        f.write("--------------------------\n")
        f.write("[ ] Authentication Assurance Level (AAL) 2 minimum\n")
        f.write("    - Multi-factor authentication enforced\n")
        f.write("    - Authentication attempts limited\n")
        f.write("    - Time-based authenticator restrictions\n\n")
        
        f.write("[ ] For AAL3 (high assurance systems)\n")
        f.write("    - Hardware-based authenticators\n")
        f.write("    - Phishing-resistant authentication\n")
        f.write("    - Verifier impersonation resistance\n\n")
        
        f.write("[ ] Authenticator Types\n")
        f.write("    - Memorized secrets (passwords) meet complexity requirements\n")
        f.write("    - Look-up secrets properly managed\n")
        f.write("    - Out-of-band devices properly enrolled\n")
        f.write("    - Single-factor OTP devices properly managed\n")
        f.write("    - Multi-factor OTP devices properly managed\n")
        f.write("    - Multi-factor cryptographic devices properly managed\n\n")
        
        f.write("CISA EMERGENCY DIRECTIVE 22-02\n")
        f.write("----------------------------\n")
        f.write("[ ] Phishing-resistant MFA for all privileged users\n")
        f.write("    - WebAuthn/FIDO2 security keys\n")
        f.write("    - PIV/CAC smart cards\n")
        f.write("    - FIPS-validated hardware tokens\n\n")
        
        f.write("[ ] Phase out vulnerable authentication methods\n")
        f.write("    - Reduce/eliminate SMS authentication\n")
        f.write("    - Reduce/eliminate voice call authentication\n")
        f.write("    - Reduce/eliminate push notifications without verification\n\n")
        
        f.write("[ ] MFA for internet-accessible systems\n")
        f.write("    - All internet-facing services protected with MFA\n")
        f.write("    - Default accounts disabled or protected with MFA\n\n")
        
        f.write("IMPLEMENTATION NOTES\n")
        f.write("------------------\n")
        f.write("The implementation of these controls should be documented in your:\n")
        f.write("- System Security Plan (SSP)\n")
        f.write("- Contingency Plan\n")
        f.write("- Authentication policies and procedures\n\n")
        
        f.write("For questions on this assessment, contact your security team.")

def analyze_compliance(duo_data: Dict[str, Any], output_dir: str) -> None:
    """Analyze data and generate compliance reports."""
    print(f"\n{Fore.CYAN}Generating compliance reports...")
    
    # Perform analysis
    auth_analysis = analyze_auth_methods(duo_data.get("auth_logs", []))
    user_analysis = analyze_users(duo_data.get("users", []))
    
    # Generate reports
    generate_cisa_report(auth_analysis, output_dir)
    print(f"  - {Fore.GREEN}CISA compliance report generated")
    
    generate_nist_report(auth_analysis, output_dir)
    print(f"  - {Fore.GREEN}NIST SP 800-63B compliance report generated")
    
    generate_fedramp_report(duo_data, output_dir, auth_analysis, user_analysis)
    print(f"  - {Fore.GREEN}FedRAMP 20x / legacy FedRAMP compliance report generated")

    ksi_path = generate_fedramp_20x_ksi_json(duo_data, output_dir, auth_analysis, user_analysis)
    print(f"  - {Fore.GREEN}FedRAMP 20x KSI evidence JSON: {ksi_path}")

    sdr_dir = generate_ksi_security_decision_record_stubs(
        duo_data, output_dir, auth_analysis, user_analysis
    )
    print(f"  - {Fore.GREEN}KSI-IAM Security Decision Record stubs: {sdr_dir}")
    
    generate_user_report(user_analysis, output_dir)
    print(f"  - {Fore.GREEN}User enrollment report generated")
    
    generate_policy_report(duo_data.get("settings", {}), output_dir)
    print(f"  - {Fore.GREEN}Policy assessment report generated")
    
    generate_executive_summary(
        auth_analysis, 
        user_analysis, 
        duo_data.get("settings", {}),
        output_dir
    )
    print(f"  - {Fore.GREEN}Executive summary generated")
    
    generate_compliance_checklist(output_dir)
    print(f"  - {Fore.GREEN}Compliance checklist generated")
    
    print(f"{Fore.GREEN}✅ All compliance reports generated successfully!")

def package_results(output_dir: str) -> str:
    """Zip all results into an archive file."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    zipfile_name = f"duo_compliance_audit_{timestamp}.zip"
    
    print(f"{Fore.CYAN}Creating archive of all assessment data...")
    with zipfile.ZipFile(zipfile_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(output_dir):
            for file in files:
                zipf.write(
                    os.path.join(root, file),
                    os.path.relpath(os.path.join(root, file), os.path.join(output_dir, '..'))
                )
    
    return zipfile_name

def main():
    """Main execution function."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Duo Security Compliance Assessment')
    parser.add_argument('--host', help='Duo API hostname (e.g., api-xxxx.duosecurity.com)')
    parser.add_argument('--ikey', help='Duo Integration Key')
    parser.add_argument('--skey', help='Duo Secret Key')
    parser.add_argument('--output-dir', help='Output directory')
    args = parser.parse_args()
    
    print_banner()
    
    # Get credentials
    if args.host and args.ikey and args.skey:
        host, ikey, skey = args.host, args.ikey, args.skey
    else:
        host, ikey, skey = get_credentials()
    
    # Create admin client
    try:
        admin_api = create_admin_client(host, ikey, skey)
    except Exception as e:
        print(f"{Fore.RED}Error creating Duo Admin API client: {str(e)}")
        sys.exit(1)
    
    # Test connection
    if not test_connection(admin_api):
        sys.exit(1)
    
    # Setup output directory
    output_dir = setup_output_dirs(args.output_dir)
    
    # Retrieve data
    duo_data = retrieve_duo_data(admin_api, output_dir)
    
    # Analyze data and generate reports
    analyze_compliance(duo_data, output_dir)
    
    # Package results
    zipfile_name = package_results(output_dir)
    
    print()
    print(f"{Fore.GREEN}✅ All compliance assessment tasks complete!")
    print("====================================================")
    print(f"Results directory: {output_dir}")
    print(f"Zipped archive:    {zipfile_name}")
    print()
    print("Key reports to review:")
    print(f"- {output_dir}/compliance_reports/executive_summary.txt")
    print(f"- {output_dir}/compliance_reports/cisa_compliance_report.txt")
    print(f"- {output_dir}/compliance_reports/nist_compliance_report.txt")
    print(f"- {output_dir}/compliance_reports/fedramp_compliance_report.txt")
    print(f"- {output_dir}/compliance_reports/fedramp_20x_ksi_evidence.json")
    print(f"- {output_dir}/compliance_reports/security_decision_records/ (KSI-IAM SDR stubs)")
    print("====================================================")

if __name__ == "__main__":
    main()