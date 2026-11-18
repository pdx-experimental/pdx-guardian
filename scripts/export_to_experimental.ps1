<#
.SYNOPSIS
    ProDocuX Export Gate - Explicit Allowlist & Boundary Validator
.DESCRIPTION
    Validates and stages ONLY an explicit approved file path allowlist from
    the source repository to the public export directory, verifying no
    reparse points / junctions / symlinks cross directory boundaries.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [string]$SourceDir = "",
    [string]$TargetDir = "",
    [switch]$Execute,
    [switch]$AllowExistingGit
)

if (-not $SourceDir) {
    $SourceDir = Split-Path -Parent $PSScriptRoot
}
if (-not $TargetDir) {
    throw "TargetDir is required. Pass -TargetDir <path-to-public-export-dir>."
}

$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "ProDocuX Explicit Allowlist Export Gate" -ForegroundColor Cyan
Write-Host "Source: $SourceDir"
Write-Host "Target: $TargetDir"
Write-Host "========================================="

function Assert-NoReparseEscape {
    param([string]$RootPath, [string]$CandidatePath)
    $resolvedRoot = [IO.Path]::GetFullPath($RootPath).TrimEnd('\') + '\'
    $resolvedCand = [IO.Path]::GetFullPath($CandidatePath)
    if (-not $resolvedCand.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
        $resolvedCand.TrimEnd('\') -ne $resolvedRoot.TrimEnd('\')) {
        throw "PATH ESCAPE VIOLATION: $CandidatePath escapes $RootPath"
    }
    $cur = $resolvedCand
    while ($cur.Length -ge $resolvedRoot.TrimEnd('\').Length) {
        if (Test-Path $cur) {
            $item = Get-Item -LiteralPath $cur -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "REPARSE/JUNCTION VIOLATION: $cur is a symlink or junction"
            }
        }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
}

Assert-NoReparseEscape -RootPath $SourceDir -CandidatePath $SourceDir
if (Test-Path $TargetDir) {
    Assert-NoReparseEscape -RootPath $TargetDir -CandidatePath $TargetDir
}
if (-not $AllowExistingGit -and (Test-Path (Join-Path $TargetDir ".git"))) {
    Write-Error "SECURITY VIOLATION: Target directory $TargetDir has a .git directory before Stage 5 sign-off!"
    exit 1
}

$prohibitedExtensions = @(".run", ".exe", ".iso", ".img", ".qcow2", ".pem", ".key", ".p12", ".pfx", ".elf", ".o", ".a", ".so")

# Explicit approved public file allowlist (no wildcard docs/ recursion)
$approvedRelativePaths = @(
    ".dockerignore",
    ".gitignore",
    ".github\workflows\ci.yml",
    "LICENSE",
    "README.md",
    "portable\include\pdx_gate_policy.h",
    "portable\include\pdx_manifest.h",
    "portable\manifest\pdx_manifest.c",
    "portable\verifier\pdx_crypto_openssl.c",
    "portable\tests\test_portable_fixtures.c",
    "qnx\guardian-gate\gate_submit.c",
    "qnx\guardian-gate\guardian_gate.c",
    "qnx\journal\pdx_journal.c",
    "qnx\journal\pdx_journal.h",
    "qnx\ecu-simulator\jitter_bench.c",
    "host\run_week1_pipeline.py",
    "host\run_week2_pipeline.py",
    "host\run_week3_pipeline.py",
    "host\run_week4_pipeline.py",
    "host\fleet-controller\build_signed_manifest.py",
    "host\fleet-controller\build_week2_fixtures.py",
    "host\fleet-controller\build_week3_fixtures.py",
    "host\pdx-adapter\pdx_lifecycle_adapter.py",
    "host\report-adapter\generate_report.py",
    "host\tests\test_week2_host_rejections.py",
    "simulator\fixtures\week1\fixtures_meta.json",
    "simulator\fixtures\week1\fw_v11.bin",
    "simulator\fixtures\week1\fw_v12_tampered.bin",
    "simulator\fixtures\week1\manifest_v11.bin",
    "simulator\fixtures\week1\manifest_v12.bin",
    "simulator\fixtures\week2\fixtures_meta.json",
    "simulator\fixtures\week2\t01_fw_v11.bin",
    "simulator\fixtures\week2\t01_manifest_v11.bin",
    "simulator\fixtures\week2\t02_fw_v12_tampered.bin",
    "simulator\fixtures\week2\t02_manifest_v12.bin",
    "simulator\fixtures\week2\t03_fw_v12.bin",
    "simulator\fixtures\week2\t03_manifest_v12_badsig.bin",
    "simulator\fixtures\week2\t04_fw_v09.bin",
    "simulator\fixtures\week2\t04_manifest_v09.bin",
    "simulator\fixtures\week2\t05_fw_v12.bin",
    "simulator\fixtures\week2\t05_manifest_v12.bin",
    "simulator\fixtures\week2\t07_fw_v12.bin",
    "simulator\fixtures\week2\t07_manifest_v12.bin",
    "simulator\fixtures\week2\t07b_fw_v12.bin",
    "simulator\fixtures\week2\t07b_manifest_v12.bin",
    "simulator\fixtures\week2\t07c_fw_v12.bin",
    "simulator\fixtures\week2\t07c_manifest_v12.bin",
    "simulator\fixtures\week3\fixtures_meta.json",
    "simulator\fixtures\week3\t01_fw_v11.bin",
    "simulator\fixtures\week3\t01_manifest_v11.bin",
    "simulator\fixtures\week3\t02_fw_v12_tampered.bin",
    "simulator\fixtures\week3\t02_manifest_v12.bin",
    "simulator\fixtures\week3\t03_fw_v12.bin",
    "simulator\fixtures\week3\t03_manifest_v12_badsig.bin",
    "simulator\fixtures\week3\t04_fw_v09.bin",
    "simulator\fixtures\week3\t04_manifest_v09.bin",
    "simulator\fixtures\week3\t05_fw_v12.bin",
    "simulator\fixtures\week3\t05_manifest_v12.bin",
    "simulator\fixtures\week3\t06_fw_v12.bin",
    "simulator\fixtures\week3\t06_manifest_v12_hwrev.bin",
    "simulator\fixtures\week3\t07_fw_v12.bin",
    "simulator\fixtures\week3\t07_manifest_v12.bin",
    "simulator\fixtures\week3\t07b_fw_v12.bin",
    "simulator\fixtures\week3\t07b_manifest_v12.bin",
    "simulator\fixtures\week3\t07c_fw_v12.bin",
    "simulator\fixtures\week3\t07c_manifest_v12.bin",
    "simulator\fixtures\week3\t08_fw_v13.bin",
    "simulator\fixtures\week3\t08_manifest_v13_replay.bin",
    "simulator\fixtures\week3\t09_fw_v13.bin",
    "simulator\fixtures\week3\t09_manifest_v13.bin",
    "simulator\fixtures\week3\t09b_fw_v14.bin",
    "simulator\fixtures\week3\t09b_manifest_v14.bin",
    "scripts\export_to_experimental.ps1",
    "scripts\gate0_qemu_probe.py",
    "scripts\qnx_week2_guest.sh",
    "scripts\qnx_week3_guest.sh",
    "scripts\qnx_week4_guest.sh",
    "scripts\run_week1_e2e.py",
    "scripts\run_week2_e2e.py",
    "scripts\run_week3_e2e.py",
    "scripts\run_week4_e2e.py",
    "docker\Dockerfile.qnx-builder",
    "docs\ARCHITECTURE.md",
    "docs\CODELAB.md",
    "docs\DEPLOYMENT.md",
    "docs\ENGINE_BOUNDARY.md",
    "docs\QNX_EVIDENCE.md",
    "docs\SECURITY.md",
    "docs\hackathon_dashboard.html",
    "tests\qnx_dual_host\qnx_target_service.c",
    "tests\qnx_dual_host\qnx_host_client.c",
    "tests\qnx_dual_host\run_qnx_dual_host.py",
    "tests\qnx_dual_host\run_oci_and_qnx_matrix.py",
    "tests\dsx_air_fleet\qnx_veh_host.c",
    "tests\dsx_air_fleet\intent_protocol.py",
    "tests\dsx_air_fleet\dist_zone_gateway.py",
    "tests\dsx_air_fleet\dist_veh_host.py",
    "tests\dsx_air_fleet\build_3j_net.py",
    "tests\dsx_air_fleet\sumo_net\arterial_3j.net.xml",
    "tests\dsx_air_fleet\run_60v_experiment.py",
    "tests\dsx_air_fleet\run_dsx_ladder.py",
    "tests\dsx_air_fleet\run_qnx_ladder.py",
    "tests\dsx_air_fleet\run_qnx_3guest.py",
    "tests\dsx_air_fleet\run_qnx_3guest_paired.py",
    "tests\dsx_air_fleet\run_qnx_crosshost.py",
    "tests\dsx_air_fleet\run_oci_lan_qnx.py",
    "tests\dsx_air_fleet\run_sumo_baseline.py",
    "tests\dsx_air_fleet\bench_qnx_vs_ubuntu.py",
    "evidence\week1\prodocux_evidence_verification.json",
    "evidence\week2\qnx_week2_results.json",
    "evidence\week2\prodocux_evidence_verification.json",
    "evidence\week3\qnx_week3_results.json",
    "evidence\week3\prodocux_evidence_verification.json",
    "evidence\week4\qnx_week4_jitter.json",
    "evidence\week4\qnx_week4_jitter_kvm.json",
    "evidence\week4\prodocux_jitter_verification.json",
    "evidence\qnx_dual_host\qnx_dual_host_results.json",
    "evidence\qnx_dual_host\qnx_dual_host_matrix.json",
    "evidence\qnx_dual_host\prodocux_qnx_dual_host_verification.json",
    "evidence\oci_dual_vm\oci_dual_vm_results_v2.json",
    "evidence\oci_dual_vm\prodocux_oci_verification_v2.json",
    "evidence\qnx_oci_bidirectional\oci_to_qnx_results.json",
    "evidence\qnx_oci_bidirectional\qnx_to_oci_results.json",
    "evidence\qnx_oci_bidirectional\prodocux_qnx_oci_bundle_verification.json",
    "tests\dsx_air_fleet\out_qnx_ladder\qnx_ladder_results.json",
    "tests\dsx_air_fleet\out_qnx_ladder\qnx_ladder_matrix.json",
    "tests\dsx_air_fleet\out_qnx_ladder\prodocux_qnx_ladder_bundle_verification.json",
    "tests\dsx_air_fleet\out_qnx_3guest\qnx_3guest_results.json",
    "tests\dsx_air_fleet\out_qnx_3guest\qnx_3guest_matrix.json",
    "tests\dsx_air_fleet\out_qnx_3guest\prodocux_qnx_3guest_bundle_verification.json",
    "tests\dsx_air_fleet\out_qnx_3guest_300_600\qnx_3guest_results.json",
    "tests\dsx_air_fleet\out_qnx_3guest_300_600\qnx_3guest_matrix.json",
    "tests\dsx_air_fleet\out_qnx_3guest_300_600\prodocux_qnx_3guest_bundle_verification.json",
    "tests\dsx_air_fleet\out_qnx_3guest_bin\qnx_3guest_results.json",
    "tests\dsx_air_fleet\out_qnx_3guest_bin\qnx_3guest_matrix.json",
    "tests\dsx_air_fleet\out_qnx_3guest_bin\prodocux_qnx_3guest_bundle_verification.json",
    "tests\dsx_air_fleet\out_qnx_3guest_paired\qnx_3guest_paired_results.json",
    "tests\dsx_air_fleet\out_qnx_crosshost\qnx_crosshost_results.json",
    "tests\dsx_air_fleet\out_qnx_crosshost\qnx_crosshost_matrix.json",
    "tests\dsx_air_fleet\out_qnx_crosshost\prodocux_qnx_crosshost_bundle_verification.json",
    "tests\dsx_air_fleet\out_qnx_crosshost_600\qnx_crosshost_results.json",
    "tests\dsx_air_fleet\out_qnx_crosshost_600\qnx_crosshost_matrix.json",
    "tests\dsx_air_fleet\out_qnx_crosshost_600\prodocux_qnx_crosshost_bundle_verification.json",
    "tests\dsx_air_fleet\out_oci_lan\qnx_oci_lan_results.json",
    "tests\dsx_air_fleet\out_sumo_baseline\sumo_baseline_results.json",
    "tests\dsx_air_fleet\out_qnx_vs_ubuntu\qnx_vs_ubuntu_results.json",
    "tests\dsx_air_fleet\out_qnx_vs_ubuntu\qnx_vs_ubuntu_kvm_results.json",
    "tests\dsx_air_fleet\out_qnx_vs_ubuntu\qnx_vs_ubuntu_kvm_binary_results.json",
    "tests\dsx_air_fleet\out_60v_paced\dsx_60v_multiseed_results.json",
    "tests\dsx_air_fleet\out_60v_paced\prodocux_dsx_60v_bundle_verification.json"
)

Write-Host "[CHECK 1] Validating $($approvedRelativePaths.Count) explicit allowlist paths & boundary safety..." -ForegroundColor Yellow
$stagedFiles = @()
foreach ($rel in $approvedRelativePaths) {
    $srcPath = Join-Path $SourceDir $rel
    if (-not (Test-Path -LiteralPath $srcPath -PathType Leaf)) {
        Write-Error "MISSING APPROVED ALLOWLIST FILE: $rel"
        exit 1
    }
    Assert-NoReparseEscape -RootPath $SourceDir -CandidatePath $srcPath
    $file = Get-Item -LiteralPath $srcPath
    if ($file.Extension -in $prohibitedExtensions) {
        Write-Error "PROHIBITED EXTENSION IN ALLOWLIST: $rel"
        exit 1
    }
    $stagedFiles += [PSCustomObject]@{ RelativePath = $rel; FullName = $file.FullName }
}
Write-Host "  -> Explicit allowlist ($($stagedFiles.Count) files) passed path & reparse checks." -ForegroundColor Green

Write-Host "[CHECK 2] Scanning workspace for stray prohibited binaries/keys..." -ForegroundColor Yellow
foreach ($ext in @("*.run", "*.exe", "*.iso", "*.img", "*.qcow2", "*.pem", "*.key", "*.p12", "*.pfx")) {
    $found = Get-ChildItem -Path $SourceDir -Include $ext -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch "\\qnx-os\\" -and $_.FullName -notmatch "\\\.venv\\" }
    if ($found) {
        Write-Error "PROHIBITED ITEM DETECTED outside qnx-os/.venv: $($found[0].FullName)"
        exit 1
    }
}
Write-Host "  -> No illegal binaries/keys detected in source code." -ForegroundColor Green

Write-Host "[CHECK 3] Scanning staged files for local paths, non-doc IPs, emails, tokens, or denylisted terms..." -ForegroundColor Yellow
$binaryExtensions = @(".bin", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".pdf")
$denyTerms = @()
if ($env:PDX_EXPORT_DENYLIST) {
    $denyTerms += $env:PDX_EXPORT_DENYLIST.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}
$localDenyFile = Join-Path $SourceDir ".export_denylist.local"
if (Test-Path $localDenyFile) {
    $denyTerms += Get-Content -LiteralPath $localDenyFile -Encoding UTF8 | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") }
}
$denyTerms = $denyTerms | Select-Object -Unique
if ($denyTerms.Count -eq 0) {
    if ($Execute) {
        Write-Error "HYGIENE GATE REFUSED: PDX_EXPORT_DENYLIST and .export_denylist.local are both empty under -Execute."
        exit 1
    }
    Write-Warning "PDX_EXPORT_DENYLIST and .export_denylist.local are both empty; private-name denylist check is skipped in dry-run."
}
$selfAllowedPatternLines = @(
    'if ($ascii -match ''(?<![A-Za-z])(?!(?:http|https|ftp|file):)[A-Za-z]:[/\\]'' -or $ascii -match ''(?i)(C:\\Users|/home/ubuntu|BEGIN [A-Z ]*PRIVATE KEY)'') {',
    'if ($line -match ''(?<![A-Za-z])(?!(?:http|https|ftp|file):)[A-Za-z]:[/\\]'') {',
    'if ($line -match ''(?i)(C:\\Users|/home/ubuntu|BEGIN [A-Z ]*PRIVATE KEY|ssh-rsa |ssh-ed25519 |ocid1\.|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{20,}|github_pat_)'') {',
    'if ($line -match ''(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'') {',
    'if ($ip -match ''^(127\.0\.0\.1|0\.0\.0\.0|10\.0\.2\.2|10\.0\.2\.15|10\.0\.0\.0|198\.51\.100\.|192\.0\.2\.|203\.0\.113\.)'') { continue }'
)
$selfAllowedArrayElements = $selfAllowedPatternLines | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }
$hygieneViolations = @()
foreach ($entry in $stagedFiles) {
    $ext = [IO.Path]::GetExtension($entry.FullName).ToLowerInvariant()
    if ($ext -in $binaryExtensions) {
        if ($ext -eq ".bin") {
            $ascii = [System.Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($entry.FullName))
            if ($ascii -match '(?<![A-Za-z])(?!(?:http|https|ftp|file):)[A-Za-z]:[/\\]' -or $ascii -match '(?i)(C:\\Users|/home/ubuntu|BEGIN [A-Z ]*PRIVATE KEY)') {
                $hygieneViolations += "$($entry.RelativePath) [binary-ascii-path-or-key]"
            }
            foreach ($term in $denyTerms) {
                if ($ascii.IndexOf($term, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $hygieneViolations += "$($entry.RelativePath) [binary-denylist:$term]"
                }
            }
        }
        continue
    }
    $lines = Get-Content -LiteralPath $entry.FullName -Encoding UTF8 -ErrorAction SilentlyContinue
    if (-not $lines) { continue }
    $isSelf = ($entry.RelativePath -eq "scripts\export_to_experimental.ps1")
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $lineNo = $i + 1
        $trimmed = $line.Trim()
        if ($isSelf -and ($trimmed -in $selfAllowedPatternLines -or $trimmed.TrimEnd(',') -in $selfAllowedArrayElements)) { continue }
        if ($line -match '(?<![A-Za-z])(?!(?:http|https|ftp|file):)[A-Za-z]:[/\\]') {
            $hygieneViolations += "$($entry.RelativePath):$lineNo [local-drive-path]"
        }
        if ($line -match '(?i)(C:\\Users|/home/ubuntu|BEGIN [A-Z ]*PRIVATE KEY|ssh-rsa |ssh-ed25519 |ocid1\.|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{20,}|github_pat_)') {
            $hygieneViolations += "$($entry.RelativePath):$lineNo [credential-or-cloud-token]"
        }
        if ($line -match '(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}') {
            $hygieneViolations += "$($entry.RelativePath):$lineNo [email-address]"
        }
        $ipMatches = [regex]::Matches($line, '\b(?:\d{1,3}\.){3}\d{1,3}\b')
        foreach ($m in $ipMatches) {
            $ip = $m.Value
            $octets = $ip.Split('.') | ForEach-Object { [int]$_ }
            if (($octets | Where-Object { $_ -gt 255 }).Count -gt 0) { continue }
            if ($ip -match '^(127\.0\.0\.1|0\.0\.0\.0|10\.0\.2\.2|10\.0\.2\.15|10\.0\.0\.0|198\.51\.100\.|192\.0\.2\.|203\.0\.113\.)') { continue }
            if ($ip -in @('8.0.0.0', '1.0.0.0', '255.255.255.0')) { continue }
            $hygieneViolations += "$($entry.RelativePath):$lineNo [non-doc-ipv4:$ip]"
        }
        foreach ($term in $denyTerms) {
            if ($line.IndexOf($term, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $hygieneViolations += "$($entry.RelativePath):$lineNo [denylist:$term]"
            }
        }
    }
}
if ($hygieneViolations.Count -gt 0) {
    Write-Error ("HYGIENE VIOLATION(S) DETECTED:`n" + ($hygieneViolations -join "`n"))
    exit 1
}
Write-Host "  -> Passed hygiene scan (local paths, non-doc/non-QEMU IPv4s, emails, cloud/git tokens, private keys, .bin ASCII, denylist)." -ForegroundColor Green

if ($Execute) {
    foreach ($entry in $stagedFiles) {
        $dest = Join-Path $TargetDir $entry.RelativePath
        Assert-NoReparseEscape -RootPath $TargetDir -CandidatePath $dest
        if ($PSCmdlet.ShouldProcess($dest, "Copy allowlist file $($entry.RelativePath)")) {
            $destDir = Split-Path -Parent $dest
            if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
            Copy-Item -Path $entry.FullName -Destination $dest -Force
        }
    }
    Write-Host "Explicit allowlist export COMPLETED." -ForegroundColor Green
} else {
    foreach ($entry in $stagedFiles) {
        $dest = Join-Path $TargetDir $entry.RelativePath
        Assert-NoReparseEscape -RootPath $TargetDir -CandidatePath $dest
        if ($WhatIfPreference) {
            $null = $PSCmdlet.ShouldProcess($dest, "Stage allowlist file $($entry.RelativePath)")
        }
    }
    Write-Host "Whitelist validation PASSED. (Dry-run only; pass -Execute at Stage 5 after full sign-off)." -ForegroundColor Green
}
