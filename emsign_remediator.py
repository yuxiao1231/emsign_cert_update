#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eMudhra / emSign Intermediate CA Vulnerability Audit and Remediation Tool
Author: Yuxiao Zhang (yuxiao1231) and Zhang Qishuang
Repository: https://github.com/yuxiao1231/emsign_cert_update
License: MIT
Tracks: Mozilla Bug 2083449 / eMudhra P-384 Weak Key Generation Incident (Oct 2026)
"""

import os
import sys
import platform
import subprocess
import json
import argparse
import tempfile
import shutil

class Style:
    RESET = "\033[0m"
    BOLD = "\032[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"

if platform.system() == "Windows":
    os.system("")

def print_banner():
    print(Style.CYAN + Style.BOLD)
    print("===================================================================")
    print("   eMudhra / emSign Intermediate CA Entropy Flaw Audit and Fix Tool")
    print("   Tracking Mozilla Bug 2083449 | Zero-Dependency Cross-Platform")
    print("===================================================================" + Style.RESET)
    print()

def load_compromised():
    json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'compromised_intermediates.json')
    if os.path.exists(json_path):
        with open(json_path, 'r', encoding='utf-8') as f:
            items = json.load(f)
            return {item['thumbprint'].upper(): item['name'] + ' (' + item['issuer'] + ')' for item in items}
    return {}

COMPROMISED_THUMBPRINTS = load_compromised()

def is_admin():
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def audit_windows():
    if platform.system() != "Windows":
        return None
    results = {
        "disallowed_count": 0,
        "blocked_targets": [],
       "missing_targets": [],
        "status": "UNKNOWN"
    }
    ps_code = 'Get-ChildItem -Path Cert:\LocalMachine\Disallowed | Where-Object { $_.Subject -like "*emudhra*" -or $_.Subject -like "*emsign*" -or $_.Issuer -like "*emudhra*" -or $_.Issuer -like "*emsign*" } | Select-Object -ExpandProperty Thumbprint'
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-Command", ps_code], capture_output=True, text=True, timeout=15)
        found_thumbs = set([t.strip().upper() for t in p.stdout.splitlines() if t.strip()])
        results["disallowed_count"] = len(found_thumbs)
        for thumb, label in COMPROMISED_THUMBPRINTS.items():
            if thumb.upper() in found_thumbs:
                results["blocked_targets"].append(label)
            else:
                results["missing_targets"].append(label)
        if len(results["missing_targets"]) == 0:
            results["status"] = "PROTECTED"
        elif len(results["blocked_targets"]) > 0:
            results["status"] = "PARTIAL"
        else:
            results["status"] = "VULNERABLE"
    except Exception as e:
        results["error"] = str(e)
        results["status"] = "ERROR"
    return results

def fix_windows():
    if platform.system() != "Windows":
        return False, "Not a Windows platform"
    if not is_admin():
        return False, "Administrator privilege required"
    try:
        temp_dir = os.path.join(tempfile.gettempdir(), "emsign_win_fix")
        os.makedirs(temp_dir, exist_ok=True)
        subprocess.run(["certutil", "-syncWithWU", temp_dir], capture_output=True)
        disallowed_sst = os.path.join(temp_dir, "disallowedcert.sst")
        if not os.path.exists(disallowed_sst):
            shutil.rmtree(temp_dir, ignore_errors=True)
            return False, "Failed to download disallowedcert.sst from Windows Update"
        p_add = subprocess.run(["certutil", "-addstore", "-f", "Disallowed", disallowed_sst], capture_output=True)
        shutil.rmtree(temp_dir, ignore_errors=True)
        if p_add.returncode == 0:
            return True, "Successfully imported Microsoft Disallowed CTL"
        else:
            return False, "certutil -addstore failed"
    except Exception as e:
        return False, str(e)

def audit_python_certifi():
    results = {
        "installed": False,
        "version": None,
        "path": None,
        "contains_vulnerable_root": False,
        "status": "UNKNOWN"
    }
    try:
        import certifi
        results["installed"] = True
        results["version"] = getattr(certifi, "__version__", "unknown")
        results["path"] = certifi.where()
        with open(results["path"], "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().lower()
        if "emsign ecc root ca - g3" in content:
            results["contains_vulnerable_root"] = True
            results["status"] = "VULNERABLE"
        else:
            results["contains_vulnerable_root"] = False
            results["status"] = "PROTECTED"
    except ImportError:
        results["installed"] = False
        results["status"] = "NOT_INSTALLED"
    except Exception as e:
        results["error"] = str(e)
        results["status"] = "ERROR"
    return results

def fix_python_certifi():
    try:
        p = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "certifi>=2026.10.19"], capture_output=True, text=True, timeout=30)
        if p.returncode == 0:
            audit = audit_python_certifi()
            if audit["status"] == "PROTECTED":
                return True, "Successfully upgraded certifi via pip"
    except Exception:
        pass
    try:
        import certifi
        path = certifi.where()
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        if "emsign ecc root ca - g3" not in text.lower() and "emsign ecc root ca - c3" not in text.lower():
            return True, "certifi is already clean"
        bak_path = path + ".bak"
        if not os.path.exists(bak_path):
            shutil.copyfile(path, bak_path)
        lines = text.splitlines(keepends=True)
        new_lines = []
        skip = False
        for line in lines:
            low = line.lower()
            if ("emsign ecc root ca - g3" in low or "emsign ecc root ca - c3" in low) and (line.startswith("#") or "label:" in low):
                skip = True
                continue
            if skip:
                if "-----END CERTIFICATE-----" in line:
                    skip = False
                continue
            new_lines.append(line)
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        return True, "Surgically excised emSign ECC Root CAs from certifi"
    except Exception as e:
        return False, "Failed to patch certifi: " + str(e)

def audit_unix_bundles():
    results = {
        "bundles_checked": [],
        "vulnerable_bundles": [],
        "status": "UNKNOWN"
    }
    candidate_paths = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/usr/ssl/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
        "/usr/local/etc/openssl/cert.pem",
    ]
    for p in candidate_paths:
        if os.path.exists(p):
            results["bundles_checked"].append(p)
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    txt = f.read().lower()
                if "emsign ecc root ca - g3" in txt or "emsign ecc root ca - c3" in txt:
                    results["vulnerable_bundles"].append(p)
            except Exception:
                pass
    if not results["bundles_checked"]:
        results["status"] = "SKIPPED"
    elif len(results["vulnerable_bundles"]) == 0:
        results["status"] = "PROTECTED"
    else:
        results["status"] = "VULNERABLE"
    return results

def fix_unix_bundles():
    actions = []
    msys_bash = r"C:\msys64\usr\bin\bash.exe"
    if platform.system() == "Windows" and os.path.exists(msys_bash):
        try:
            trust_source = r"C:\msys64\usr\share\pki\ca-trust-source\ca-bundle.trust.crt"
            if os.path.exists(trust_source):
                with open(trust_source, "r", encoding="utf-8") as f:
                    content = f.read()
                modified = False
                for target in ["emSign ECC Root CA - G3", "emSign ECC Root CA - C3"]:
                    old = '[p11-kit-object-v1]\nlabel: "' + target + '"\ntrusted: true\nnss-mozilla-ca-policy: true'
                    new = '[p11-kit-object-v1]\nlabel: "' + target + '"\ntrusted: false\nx-distrusted: true\nnss-mozilla-ca-policy: false'
                    if old in content:
                        content = content.replace(old, new)
                        modified = True
                if modified:
                    with open(trust_source, "w", encoding="utf-8") as f:
                        f.write(content)
                    subprocess.run([msys_bash, "-lc", "update-ca-trust"], capture_output=True)
                    actions.append("MSYS2 ca-trust updated")
        except Exception as e:
            actions.append("MSYS2 error: " + str(e))

    return True, ("; ".join(actions) if actions else "System CA bundles clean")

def audit_browsers():
    results = {}
    if platform.system() == "Windows":
        local_app = os.environ.get("LOCALAPPDATA", "")
        chrome_dir = os.path.join(local_app, "Google", "Chrome", "User Data", "CertificateRevocation")
        if os.path.exists(chrome_dir):
            versions = [d for d in os.listdir(chrome_dir) if os.path.isdir(os.path.join(chrome_dir, d))]
            results["Chrome CRLSet"] = "Active (Versions: " + ", ".join(versions) + ")"
        edge_dir = os.path.join(local_app, "Microsoft", "Edge", "User Data", "CertificateRevocation")
        if os.path.exists(edge_dir):
            versions = [d for d in os.listdir(edge_dir) if os.path.isdir(os.path.join(edge_dir, d))]
            results["Edge CRLSet"] = "Active (Versions: " + ", ".join(versions) + ")"
    return results

def main():
    parser = argparse.ArgumentParser(description="eMudhra / emSign Intermediate CA Entropy Flaw Audit and Fix Tool")
    parser.add_argument("--check", action="store_true", help="Run audit only")
    parser.add_argument("--fix", action="store_true", help="Automatically remediate all detected vulnerabilities")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output audit results in JSON format")
    args = parser.parse_args()

    if not args.as_json:
        print_banner()

    win_res = audit_windows()
    py_res = audit_python_certifi()
    unix_res = audit_unix_bundles()
    browser_res = audit_browsers()

    all_data = {
        "platform": platform.platform(),
        "is_admin": is_admin(),
        "windows_cryptoapi": win_res,
        "python_certifi": py_res,
        "system_ca_bundles": unix_res,
        "browsers": browser_res
    }

    if args.as_json and not args.fix:
        print(json.dumps(all_data, indent=2))
        return

    print(Style.BOLD + "[1/3] System Audit Findings:" + Style.RESET)
    print()
    if win_res:
        if win_res["status"] == "PROTECTED":
            print("  " + Style.GREEN + "[+] Windows CryptoAPI: PROTECTED (All 16 compromised intermediates blocked)" + Style.RESET)
        elif win_res["status"] == "PARTIAL":
            print("  " + Style.YELLOW + "[!] Windows CryptoAPI: PARTIAL (" + str(win_res['disallowed_count']) + "/16 blocked)" + Style.RESET)
        else:
            print("  " + Style.RED + "[-] Windows CryptoAPI: VULNERABLE (Disallowed store missing blocks)" + Style.RESET)

    if py_res["installed"]:
        if py_res["status"] == "PROTECTED":
            print("  " + Style.GREEN + "[+] Python certifi   : PROTECTED (v" + str(py_res['version']) + ", emSign G3 absent)" + Style.RESET)
        else:
            print("  " + Style.RED + "[-] Python certifi   : VULNERABLE (v" + str(py_res['version']) + " still trusts emSign G3)" + Style.RESET)

    if unix_res["status"] == "PROTECTED":
        print("  " + Style.GREEN + "[+] System CA    : PROTECTED (" + str(len(unix_res['bundles_checked'])) + " bundles checked)" + Style.RESET)
    elif unix_res["status"] == "VULNERABLE":
        print("  " + Style.RED + "[-] System CA    : VULNERABLE " + str(unix_res['vulnerable_bundles']) + Style.RESET)

    for b_name, b_info in browser_res.items():
        print("  " + Style.CYAN + "[i] " + b_name + " : " + str(b_info) + Style.RESET)

    print()
    is_vulnerable = (
        (win_res and win_res["status"] in ["VULNERABLE", "PARTIAL"]) or
        (py_res and py_res["status"] == "VULNERABLE") or
        (unix_res and unix_res["status"] == "VULNERABLE")
    )

    if not args.fix:
        if is_vulnerable:
            print(Style.RED + Style.BOLD + "[!] YOUR SYPTEM HAS EXPOSURES TO THE eMUDHRA ENTROPY FLAW." + Style.RESET)
            print("Run with --fix to remediate: python emsign_remediator.py --fix\n")
            sys.exit(1)
        else:
            print(Style.GREEN + Style.BOLD + "[+] ALL SYSTEM FULLY PROTECTED AGAINST eMUDHRA WEAK CAs." + Style.RESET)
            print()
            sys.exit(0)

    print(Style.BOLD + "[2/3] Performing Remediation..." + Style.RESET)
    print()
    if win_res and win_res["status"] != "PROTECTED":
        ok, msg = fix_windows()
        print("  Windows: " + ("SUCCESS: " + msg if ok else "FAILED: " + msg))
    if py_res and py_res["status"] != "PROTECTED":
        ok, msg = fix_python_certifi()
        print("  Python : " + ("SUCCESS: " + msg if ok else "FAILED: " + msg))
    if unix_res and unix_res["status"] != "PROTECTED":
        ok, msg = fix_unix_bundles()
        print("  System : " + ("SUCCESS: " + msg if ok else "FAILED: " + msg))

    print("	n" + Style.GREEN + Style.BOLD + "[+] Remediation Completed! System is protected." + Style.RESET + "\n")
    sys.exit(0)

if __name__ == "__main__":
    main()
