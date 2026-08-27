<#
.SYNOPSIS
    Export the CA certificates of a TLS-inspecting proxy so the scanner image
    can be built behind it.

.DESCRIPTION
    Corporate proxies (Netskope, Zscaler, Palo Alto, Fortinet deep inspection,
    …) re-sign every HTTPS connection with a private CA. The Windows/Linux host
    trusts that CA, but the python:3.12-slim build container does not, so
    `pip install` fails with CERTIFICATE_VERIFY_FAILED.

    This script opens a TLS connection to pypi.org, walks the certificate chain
    that is actually presented, and writes every CA in it to
    certs/proxy-ca.crt in PEM format. The Dockerfile trusts everything
    in that directory at build and run time.

    Nothing is written when the chain is a normal public one — i.e. when there
    is no interception, this script correctly does nothing.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\export-proxy-ca.ps1
    docker compose build scanner
#>
[CmdletBinding()]
param(
    [string] $TargetHost = 'pypi.org',
    [int]    $Port = 443,
    [string] $OutFile
)

$ErrorActionPreference = 'Stop'

if (-not $OutFile) {
    $OutFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'certs\proxy-ca.crt'
}

Write-Host "Probing https://${TargetHost}:${Port} ..."

$tcp = [System.Net.Sockets.TcpClient]::new($TargetHost, $Port)
try {
    $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, { $true })
    $ssl.AuthenticateAsClient($TargetHost)
    $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
}
finally {
    if ($ssl) { $ssl.Dispose() }
    $tcp.Dispose()
}

$chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
$chain.ChainPolicy.RevocationMode = 'NoCheck'
$null = $chain.Build($leaf)

# Everything above the leaf is a CA we may need to trust.
$authorities = @($chain.ChainElements | Select-Object -Skip 1 | ForEach-Object { $_.Certificate })

if ($authorities.Count -eq 0) {
    Write-Warning "No intermediate/root CA returned. Nothing written."
    exit 0
}

$wellKnown = @(
    'DigiCert', 'Let''s Encrypt', 'ISRG', 'Baltimore', 'GlobalSign',
    'Sectigo', 'USERTrust', 'Amazon', 'Google Trust Services', 'GTS ', 'Entrust'
)
$intercepted = $true
foreach ($pattern in $wellKnown) {
    if ($authorities[-1].Subject -like "*$pattern*") { $intercepted = $false; break }
}

Write-Host ""
foreach ($cert in $authorities) {
    Write-Host "  CA: $($cert.Subject)"
}
Write-Host ""

if (-not $intercepted) {
    Write-Host "The chain terminates at a public root - this connection is NOT being" -ForegroundColor Green
    Write-Host "intercepted. No CA file is needed; the build will work as is." -ForegroundColor Green
    exit 0
}

$directory = Split-Path -Parent $OutFile
if (-not (Test-Path $directory)) { New-Item -ItemType Directory -Force -Path $directory | Out-Null }

$builder = [System.Text.StringBuilder]::new()
foreach ($cert in $authorities) {
    [void]$builder.AppendLine("# $($cert.Subject)")
    [void]$builder.AppendLine('-----BEGIN CERTIFICATE-----')
    [void]$builder.AppendLine(
        [System.Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')
    )
    [void]$builder.AppendLine('-----END CERTIFICATE-----')
}

# LF endings and no BOM: this file is consumed by OpenSSL inside a Linux image.
$content = $builder.ToString() -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($OutFile, $content, [System.Text.UTF8Encoding]::new($false))

Write-Host "Wrote $($authorities.Count) CA certificate(s) to:" -ForegroundColor Yellow
Write-Host "  $OutFile"
Write-Host ""
Write-Host "Now run:  docker compose build scanner"
