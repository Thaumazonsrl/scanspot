# Extra CA certificates

Drop any PEM-encoded `*.crt` file here and the scanner image will trust it, both
while it is being built and while it is running.

This exists for one reason: **TLS-inspecting corporate proxies**. Netskope,
Zscaler, Palo Alto, Fortinet deep inspection and friends re-sign every HTTPS
connection with a private CA. The host trusts it, the `python:3.12-slim` build
container does not, and `pip install` dies with:

```
SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
certificate verify failed: self-signed certificate in certificate chain'))
```

Generate the file automatically from whatever your machine is actually being
served:

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File scripts\export-proxy-ca.ps1
```

```bash
# Linux / macOS
./scripts/export-proxy-ca.sh
```

Then rebuild:

```bash
docker compose build scanner
```

Notes:

* `*.crt` in this directory is **gitignored** — the CA is specific to the
  network you build on, and the client's VM may sit behind a different one (or
  none at all). Re-run the export script on each build host.
* Only files ending in `.crt` are picked up, and each must be PEM
  (`-----BEGIN CERTIFICATE-----`). A DER file renamed to `.crt` will be ignored.
* An empty directory is the normal case. The build works fine without any
  certificate here.
