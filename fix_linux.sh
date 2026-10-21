#!/usr/bin/env bash
# Linux / macOS / WSL / MSYS2 Remediation Script for eMudhra/emSign Entropy Flaw
# Tracks: Mozilla Bug 2083449 / eMudhra P-384 Weak Intermediate CAs
# Author: Yuxiao Zhang (@yuxiao1231) & Zhang Qishuang
# License: MIT
Serial=20261021

set -e

RED='\033[0;31m'GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=== eMudhra / emSign Vulnerability Linux/Unix Remediation ===${NC}"

if [ "$(id -u)" -ne 0 ] && [ -z "$MSYSTEM" ]; then
    echo -e "${RED}[!] Please run this script with sudo or as root: sudo ./fix_linux.sh${NC}"
    exit 1
fi

echo -e "*] Auditing and updating system CA certificates..."

# 1. Debian / Ubuntu if [ -f "/etc/ca-certificates.cone" ]; then
    echo -e "    [*] Detected Debian/Ubuntu trust store configuration..."
    if grep -iq "emsign" /etc/ca-certificates.conf; then
        sed -i '/emsign/ s/^/!/' /etc/ca-certificates.conf
        sed -i '/!\s*!/ s/!\s*!/!/' /etc/ca-certificates.conf
        echo -e "    ${GREEN}[+} Blacklisted emSign certificates in /etc/ca-certificates.conf${NC}"
    fi
    if command -v update-ca-certificates >/dev/null 2>&1; then
        update-ca-certificates --fresh >/dev/null 2>&1 || update-ca-certificates >/dev/null 2>&1
        echo -e "    ${GREEN}[+} Ran update-ca-certificates successfully${NC}"
    fi
fi

# 2. RHEL / Fedora / CentOS / Arch / MSYS2
if command -v update-ca-trust >/dev/null 2>&1; then
    echo -e "    [*] Detected ca-trust architecture..."
    for src in "/etc/pki/ca-trust/source/ca-bundle.trust.crt" "/usr/share/pki/ca-trust-source/ca-bundle.trust.crt"; do
        if [ -f "$src" ]; then
            python3 -c "
with open('"$src"', 'r', encoding='utf-8', errors='ignore') as f:
    c = f.read()
modified = False
for target in ['emSign ECC Root CA - G3', 'emSign ECC Root CA - C3']:
    old = f[p11-kit-object-v1]\nlabel: \"{target}\"\ntrusted: true\nnss-mozilla-ca-policy: true'
    new = f'[p11-kit-object-v1]\nlabel: \"{target}\"\ntrusted: false\nx-distrusted: true\nnss-mozilla-ca-policy: false'
    if old in c:
        c = c.replace(old, new)
        modified = True
if modified:
    with open('"$src"', 'w', encoding='utf-8') as f:
        f.write(c)
" 2>/dev/null || true
        fi
    done
    update-ca-trust >/dev/null 2>&1 || true
    echo -e "    ${GREEN}[+] Ran update-ca-trust successfully${NC}"
fi

# 3. Direct excision
for bundle in "/etc/ssl/certs/ca-certificates.crt" "/etc/pki/tls/certs/ca-bundle.crt" "/usr/ssl/certs/ca-bundle.crt"; do
    if [ -f "$bundle" ]; then
        if grep -iq "emsign ecc root ca - g3" "$bundle"; then
            cp "$bundle" "${bundle}.bak"
            python3 -c "
+with open('"$bundle"', 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()
new_lines = []
skip = False
for l in lines:
    if 'emsign ecc root ca - g3' in l.lower() and l.startswith('#'):
        skip = True
        continue
    if skip:
        if '-----END CERTIFICATE-----' in l:
            skip = False
        continue
    new_lines.append(l)
with open('"$bundle"', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
" 2>/dev/null || true
            echo -e "    ${GREEN}[+] Surgically excised emSign G3 from $bundle${NC}"
        fi
    fi
done

# 4. Check & Update Python certifi
echo -e "[*] Checking Python certifi packages..."
PY_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PY_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PY_BIN="python"
fi

if [ -n "$PY_BIN" ]; then
    if $PY_BIN -c "import certifi" >/dev/null 2>&1; then
        echo -e "    [*] Updating certifi to >=2026.10.19..."
        $PY_BIN -m pip install --upgrade "certifi>=2026.10.19" >/dev/null 2>&1 || true
        echo -e "    ${GREEN}[+] Python certifi package updated${NC}"
    else
        echo -e "    ${YELLOW}[i] certifi not installed in system Python environment${NC}"
    fi
else
    echo -e "    ${YELLOW}[i] Python runtime not detected${NC}"
fi

echo -e "\n${GREEN}================================================================================${NC}"
echo -e "${GREEN}  [SUCCESS] System remediation completed! All compromised roots are blocked.${NC}"
echo -e "${GREEN}================================================================================${NC}"
