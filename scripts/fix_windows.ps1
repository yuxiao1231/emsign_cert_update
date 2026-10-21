# Windows PowerShell Remediation Engine for eMudhra/emSign Entropy Flaw
# Tracks: Mozilla Bug 2083449 / eMudhra P-384 Weak Intermediate CAs
# Author: Yuxiao Zhang (@yuxiao1231) & Zhang Qishuang
# License: MIT

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "eMudhra / emSign Remediation Engine"

function Write-Color([string]$text, [ConsoleColor]$color) {
    Write-Host $text -ForegroundColor $color
}

Write-Color "=== eMudhra / emSign Intermediate CA Vulnerability Audit & Fix ===" Cyan
Write-Color "Checking Windows System Certificate Stores (CryptoAPI Disallowed List)...`n" Gray

# The 16 compromised intermediate certificates disclosed in October 2026
$compromisedCertificates = @(
    @{ Name = "EM EV TLS CA - G3B"; Issuer = "emSign Root TLS CA - G3"; Thumbprint = "F33ACD1F5D31AA81AC18C72C928446226D3D5914" },
    @{ Name = "EM OV CS CA - G3B (Cross-signed)"; Issuer = "AAA Certificate Services (Comodo)"; Thumbprint = "EE26D7AE3CC71718F6E07D7D0095076F0C158F63" },
    @{ Name = "EM OV CS CA - G3B"; Issuer = "emSign Root CS CA - G3"; Thumbprint = "D33195A244046A3263FB5E0E83C6803A5B2E7BC3" },
    @{ Name = "EM EV TLS CA - G3C"; Issuer = "emSign Root TLS CA - G3"; Thumbprint = "C988F3D0CC1629FFC43165D6464C9B6EF73D6E48" },
    @{ Name = "EM DV TLS CA - G3B"; Issuer = "emSign Root TLS CA - G3"; Thumbprint = "A99B289464F3B44343270A7A1E910F02370483FE" },
    @{ Name = "EM DV TLS CA - G3C"; Issuer = "emSign Root TLS CA - G3"; Thumbprint = "8AD23BC78845D6FAAE1D534BAC89F0E36BA55A11" },
    @{ Name = "EM EV TLS CA - G3C (Cross-signed)"; Issuer = "AAA Certificate Services (Comodo)"; Thumbprint = "8588708E875A1F8AA83524F3559080F7E17068C7" },
    @{ Name = "EM OV CS CA - G3C (Cross-signed)"; Issuer = "AAA Certificate Services (Comodo)"; Thumbprint = "7FDE64753A957B98F172FD2AB0D922551909C7BA" },
    @{ Name = "EM OV TLS CA - G3C"; Issuer = "emSign Root TLS CA - G3"; Thumbprint = "7FCC31AAB874CE6C8EE8584F54CFD08646B54117" },
    @{ Name = "EM OV TLS CA - G3B"; Issuer = "emSign Root TLS CA - G3"; Thumbprint = "5F014E0DB3BB8F950E0598AB280846D383FC57BE" },
    @{ Name = "EM OV TLS CA - G3B (Cross-signed)"; Issuer = "AAA Certificate Services (Comodo)"; Thumbprint = "5DFA19197D1C1CF629AF7C0CD865543C5050227C" },
    @{ Name = "EM DV TLS CA - G3C (Cross-signed)"; Issuer = "AAA Certificate Services (Comodo)"; Thumbprint = "4B0944C14F8C2CCBA4E4F32104AD920FA15EE331" },
    @{ Name = "EM OV TLS CA - G3C (Cross-signed)"; Issuer = "AAA Certificate Services (Comodo)"; Thumbprint = "305FC1E253DCAB71B95D4995DAE3CB09D562F22A" },
    @{ Name = "EM OV CS CA - G3C"; Issuer = "emSign Root CS CA - G3"; Thumbprint = "1F4A5D178F8B6A8EF0F6784155BD5FEA91158B12" },
    @{ Name = "EM EV TLS CA - G3B (Cross-signed)"; Issuer = "AAA Certificate Services (Comodo)"; Thumbprint = "19069BD6533BFF93FB67C71FB3376B4EA7402C3B" },
    @{ Name = "EM DV TLS CA - G3B (Cross-signed)"; Issuer = "AAA Certificate Services (Comodo)"; Thumbprint = "1396BE1372BC93DFA2A433CA964DBA91548A6E57" }
)

# Step 1: Audit Current Disallowed Store
$currentDisallowed = Get-ChildItem -Path Cert:\LocalMachine\Disallowed -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Thumbprint
$missingCount = 0

foreach ($cert in $compromisedCertificates) {
    if ($currentDisallowed -notcontains $cert.Thumbprint) {
        $missingCount++
    }
}

if ($missingCount -eq 0) {
    Write-Color "[+] Windows Disallowed Certificate Store is already fully protected!" Green
    Write-Color "    All 16 compromised intermediate certificates are blocked locally.`n" Green
} else {
    Write-Color "[!] Found $missingCount unblocked intermediate certificates in local store." Yellow
    Write-Color "[*] Syncing official Microsoft Disallowed Certificate Trust List (CTL)..." Cyan
    
    $tempDir = Join-Path $env:TEMP ("emsign_fix_" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        certutil.exe -syncWithWU $tempDir | Out-Null
        $disallowedSst = Join-Path $tempDir "disallowedcert.sst"
        
        if (Test-Path $disallowedSst) {
            Write-Color "[*] Importing Microsoft Disallowed Certificate Trust List into LocalMachine\Disallowed..." Cyan
            certutil.exe -addstore -f Disallowed $disallowedSst | Out-Null
            Write-Color "[+] Import completed successfully!`n" Green
        } else {
            Write-Color "[-] Failed to retrieve disallowedcert.sst from Windows Update." Red
        }
    }
    catch {
        Write-Color "[-] Error during certutil execution: $_" Red
    }
    finally {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Step 2: Verification of All 16 Certificates
Write-Color "--- Verification Status ---" White
$verifiedDisallowed = Get-ChildItem -Path Cert:\LocalMachine\Disallowed -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Thumbprint
$allSecured = $true

foreach ($cert in $compromisedCertificates) {
    if ($verifiedDisallowed -contains $cert.Thumbprint) {
        Write-Host "  [OK] " -ForegroundColor Green -NoNewline
        Write-Host "$($cert.Name) " -ForegroundColor White -NoNewline
        Write-Host "($($cert.Issuer))" -ForegroundColor Gray
    } else {
        Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline
        Write-Host "$($cert.Name) - NOT BLOCKED" -ForegroundColor Red
        $allSecured = $false
    }
}

# Step 3: Check Browser Component Revocation Lists (CRLSet)
Write-Color "`n--- Browser Component Revocation Lists ---" White

$chromeRevDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\CertificateRevocation"
if (Test-Path $chromeRevDir) {
    $crlVersions = (Get-ChildItem -Path $chromeRevDir -Directory).Name -join ", "
    Write-Color "  [OK] Google Chrome CRLSet is active (Versions: $crlVersions)" Green
} else {
    Write-Color "  [?] Google Chrome not found or default profile path differs." Gray
}

$edgeRevDir = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\CertificateRevocation"
if (Test-Path $edgeRevDir) {
    $crlVersions = (Get-ChildItem -Path $edgeRevDir -Directory).Name -join ", "
    Write-Color "  [OK] Microsoft Edge CRLSet is active (Versions: $crlVersions)" Green
} else {
    Write-Color "  [?] Microsoft Edge CRLSet not found or default profile path differs." Gray
}

# Summary
Write-Host ""
if ($allSecured) {
    Write-Color "===============================================================================" Green
    Write-Color "  [SUCCESS] All 16 compromised intermediate certificates are verified BLOCKED!" Green
    Write-Color "  Your Windows system TLS/SSL stack is completely protected." Green
    Write-Color "===============================================================================" Green
    exit 0
} else {
    Write-Color "===============================================================================" Red
    Write-Color "  [WARNING] Some certificates could not be verified in the Disallowed store." Red
    Write-Color "  Please ensure you ran this script with Administrator privileges." Red
    Write-Color "===============================================================================" Red
    exit 1
}
