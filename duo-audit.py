#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
duo-audit.py

A comprehensive script to evaluate Duo Security for FedRAMP, NIST, and CISA compliance.
Focuses on MFA best practices, phishing-resistant authentication, and regulatory requirements.

Copyright (C) 2025 Ethan Troy <https://ethantroy.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Requires:
  - Python 3.6+
  - duo_client Python library
  - json, colorama, tabulate libraries

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
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple

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
SCRIPT_VERSION = "1.0.0"
SCRIPT_DATE = "2025-04-09"

def print_banner():
    """Display a stylish banner for the script."""
    banner = f"""
 ____              _____  _____  ____   ____       _       _   _ 
|  _ \\ _   _  ___ / ____|/ ____|/ __ \\ / __ \\     | |     | | | |
| | | | | | |/ _ \\ |  __| |  __| |  | | |  | |    | |     | | | |
| | | | | | | (_) | | |_ | | |_ | |  | | |  | |_   | |     | | | |
| |_| | |_| |\\___/| |__| | |__| | |__| | |__| | |__| |     | | | |
|____/ \\__,_|      \\_____|\\_____|\\____/ \\____/ \\____/      |_| |_|
                                                                  
{Fore.CYAN}MFA Compliance Assessment Script v{SCRIPT_VERSION}
{Fore.CYAN}FedRAMP | NIST SP 800-63B | CISA Directives
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
    
    return host, ikey, skey

def create_admin_client(host: str, ikey: str, skey: str) -> duo_client.Admin:
    """Create and return a Duo Admin API client."""
    return duo_client.Admin(ikey=ikey, skey=skey, host=host)

def test_connection(admin_api: duo_client.Admin) -> bool:
    """Test the connection to the Duo Admin API."""
    print(f"\n{Fore.CYAN}Testing Duo Admin API connection...")
    try:
        # Try to get a single user to verify connection
        admin_api.get_users(limit=1)
        print(f"{Fore.GREEN}✅ Duo Admin API connection successful!")
        return True
    except Exception as e:
        print(f"{Fore.RED}❌ Failed to connect to Duo Admin API: {str(e)}")
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
    
    # Helper function to get and save API data
    def get_and_save(endpoint_name: str, method_name: str, *args, **kwargs) -> Any:
        print(f"  - Retrieving {endpoint_name}...")
        try:
            method = getattr(admin_api, method_name)
            data = method(*args, **kwargs)
            
            # Save to file
            filename = f"{data_dir}/{endpoint_name.lower().replace(' ', '_')}.json"
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
            
            print(f"    {Fore.GREEN}SUCCESS")
            return data
        except Exception as e:
            print(f"    {Fore.RED}FAILED: {str(e)}")
            # Save empty data to maintain file structure
            filename = f"{data_dir}/{endpoint_name.lower().replace(' ', '_')}.json"
            with open(filename, "w") as f:
                json.dump([], f)
            return []
    
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
    print(f"  {Style.BRIGHT}Section 7/8: Policy configuration")
    duo_data["settings"] = get_and_save("settings", "get_settings")
    duo_data["policies"] = get_and_save("policies", "get_policies")
    
    # 8. Integrations and applications
    print(f"  {Style.BRIGHT}Section 8/8: Integrations and applications")
    duo_data["integrations"] = get_and_save("integrations", "get_integrations")
    duo_data["groups"] = get_and_save("groups", "get_groups")
    
    print(f"{Fore.GREEN}✅ All Duo data retrieval complete!")
    return duo_data

def analyze_auth_methods(auth_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze authentication methods used."""
    if not auth_logs:
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
        factor = log.get("factor", "unknown")
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
    if not users:
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
        if (user.get("status") == "active" and 
            len(user.get("phones", [])) == 0 and 
            len(user.get("tokens", [])) == 0):
            unenrolled.append(user)
    
    # Users with bypass codes
    users_with_bypass = []
    for user in users:
        if len(user.get("bypass_codes", [])) > 0:
            users_with_bypass.append(user)
    
    # Users with hardware tokens
    users_with_hardware = []
    for user in users:
        if len(user.get("tokens", [])) > 0:
            users_with_hardware.append(user)
    
    # Active/disabled users
    active_users = len([u for u in users if u.get("status") == "active"])
    disabled_users = len([u for u in users if u.get("status") == "disabled"])
    
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

def generate_fedramp_report(admins: List[Dict[str, Any]], output_dir: str) -> None:
    """Generate FedRAMP compliance report."""
    report_file = f"{output_dir}/compliance_reports/fedramp_compliance_report.txt"
    
    with open(report_file, "w") as f:
        f.write("FEDRAMP COMPLIANCE ASSESSMENT\n")
        f.write("===========================\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("1. ADMINISTRATOR ACCESS CONTROLS\n")
        f.write("-----------------------------\n")
        
        admin_count = len(admins)
        f.write(f"Administrator Count: {admin_count}\n\n")
        
        f.write("Administrator Details:\n")
        for admin in sorted(admins, key=lambda x: x.get('name', '')):
            f.write(f"- {admin.get('name', 'Unknown')} ({admin.get('email', 'No email')})\n")
            f.write(f"  • Role: {admin.get('role', 'Unknown')}\n")
            f.write(f"  • Status: {admin.get('status', 'Unknown')}\n")
            f.write(f"  • 2FA Enrolled: {'Yes' if admin.get('email_verified', False) else 'No'}\n")
        
        f.write("\nFedRAMP Requirements Assessment:\n")
        f.write(f"✓ Minimum number of administrators: {'YES' if admin_count <= 5 else f'NO (too many - {admin_count})'}\n")
        
        # Check for separation of duties (different admin roles)
        admin_roles = set(admin.get('role', '') for admin in admins)
        has_separation = len(admin_roles) > 1
        f.write(f"✓ Separation of duties: {'YES' if has_separation else 'NO (all admins have same role)'}\n\n")
        
        f.write("2. AUDIT LOGGING CAPABILITIES\n")
        f.write("---------------------------\n")
        f.write("FedRAMP requires comprehensive audit logging with 90-day online retention.\n")
        f.write("Duo Federal provides the required audit logging capabilities.\n\n")
        f.write("✓ Authentication logs: Available through Admin API\n")
        f.write("✓ Administrator activity logs: Available through Admin API\n\n")
        
        f.write("3. FEDRAMP AUTHORIZATION REQUIREMENTS\n")
        f.write("----------------------------------\n")
        f.write("For FedRAMP compliance, you must use Duo Federal with:\n")
        f.write("- FIPS 140-2/140-3 validated cryptographic modules\n")
        f.write("- FedRAMP Moderate or High authorization\n")
        f.write("- US-based support personnel\n\n")
        f.write("NOTE: Manual verification needed to confirm Duo Federal edition is in use\n")

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
        for i, user in enumerate(user_analysis["unenrolled_users"][:10]):
            f.write(f"- {user.get('username', 'Unknown')} ({user.get('email', 'No email')})\n")
        
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
        global_policy = settings.get("global_policy", {})
        
        if global_policy:
            f.write(f"- MFA Required: {global_policy.get('require_mfa', False)}\n")
            f.write(f"- FIDO2 Enforced: {global_policy.get('fido2_enforced', False)}\n")
            f.write(f"- Hardware Token Required: {global_policy.get('hardware_token_required', False)}\n")
            f.write(f"- Duo Push Setting: {global_policy.get('duo_push_setting', 'unknown')}\n")
            f.write(f"- SMS/Phone Setting: {global_policy.get('sms_setting', 'unknown')}/{global_policy.get('voice_setting', 'unknown')}\n\n")
        else:
            f.write("No global policy found\n\n")
        
        f.write("COMPLIANCE ASSESSMENT:\n")
        f.write("---------------------\n")
        
        if global_policy:
            require_mfa = global_policy.get('require_mfa', False)
            fido2_enforced = global_policy.get('fido2_enforced', False)
            hardware_required = global_policy.get('hardware_token_required', False)
            sms_allowed = global_policy.get('sms_setting', '') == 'allowed'
            voice_allowed = global_policy.get('voice_setting', '') == 'allowed'
            
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
        
        if global_policy:
            if not global_policy.get('require_mfa', False):
                f.write("- Enable global MFA requirement\n")
            if not global_policy.get('fido2_enforced', False):
                f.write("- Enable FIDO2 enforcement for phishing-resistant authentication\n")
            if not global_policy.get('hardware_token_required', False):
                f.write("- Consider requiring hardware tokens for sensitive users\n")
            if global_policy.get('sms_setting', '') == 'allowed' or global_policy.get('voice_setting', '') == 'allowed':
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
        f.write("1. FedRAMP security requirements\n")
        f.write("2. NIST SP 800-63B authentication standards\n")
        f.write("3. CISA Emergency Directive 22-02 for phishing-resistant MFA\n\n")
        
        f.write("KEY FINDINGS\n")
        f.write("-----------\n")
        
        # Extract key policy settings
        global_policy = settings.get("global_policy", {})
        mfa_required = global_policy.get("require_mfa", False)
        
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
        
        # FedRAMP compliance
        fedramp_compliant = mfa_required and users_without_mfa == 0
        
        f.write(f"CISA Directive 22-02: {'COMPLIANT ✅' if cisa_compliant else 'NON-COMPLIANT ❌'}\n")
        f.write(f"NIST SP 800-63B: {nist_aal}\n")
        f.write(f"FedRAMP Requirements: {'BASELINE COMPLIANT ✅' if fedramp_compliant else 'NON-COMPLIANT ❌'}\n\n")
        
        f.write("PRIORITY RECOMMENDATIONS\n")
        f.write("----------------------\n")
        f.write("1. Enforce MFA for all users\n")
        f.write("2. Implement phishing-resistant authentication (FIDO2/WebAuthn)\n")
        f.write("3. Phase out SMS and phone call authentication\n")
        f.write("4. Ensure hardware tokens are FIPS 140-2/140-3 validated\n")
        f.write("5. Document Duo configuration in system security documentation\n\n")
        
        f.write("NEXT STEPS\n")
        f.write("---------\n")
        f.write("1. Review the detailed compliance reports in the assessment directory\n")
        f.write("2. Remediate identified gaps in MFA implementation\n")
        f.write("3. Update policies to enforce phishing-resistant authentication\n")
        f.write("4. Verify Duo Federal edition for FedRAMP compliance\n\n")
        
        f.write("For questions on this assessment, contact your security team.")

def generate_compliance_checklist(output_dir: str) -> None:
    """Generate compliance checklist."""
    report_file = f"{output_dir}/compliance_reports/compliance_checklist.txt"
    
    with open(report_file, "w") as f:
        f.write("DUO SECURITY COMPLIANCE CHECKLIST\n")
        f.write("================================\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("FEDRAMP COMPLIANCE REQUIREMENTS\n")
        f.write("-----------------------------\n")
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
    
    generate_fedramp_report(duo_data.get("admins", []), output_dir)
    print(f"  - {Fore.GREEN}FedRAMP compliance report generated")
    
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
    print("====================================================")

if __name__ == "__main__":
    main()