# Canon PIXMA TS3451 — Firmware Research Write-up

**Date:** July 2026  
**Author:** TheFrenchGuy  
**Status:** Personal research on owned hardware  
**Firmware version:** V00.15.RC1.JAPAN-CANON

---

## TL;DR

First documented firmware analysis of the Canon PIXMA TS3451 (2020+ series). Using a Raspberry Pi 5 GPIO as an SPI programmer, I dumped the full 16MB flash (Winbond W25Q128). Found 3 decompressed zlib firmware blobs containing the full network stack, web interface, and crypto library (MatrixSSL/BSAFE). The firmware update manifest is AES-GCM encrypted — the key is derived at runtime via a software Asset Store and never exists in plaintext on the flash. Looking for help identifying the key derivation scheme.

**What's new:** All public Canon PIXMA firmware research (Synacktiv, Contextis, leecher1337) targets 2010-2015 models. The TS3400 series has never been documented publicly, as far as I know.

---

## Goal

I wanted to turn a broken Canon PIXMA TS3451 (can't print anymore) into a scanner-only device. Turns out the scanner subsystem is completely independent in the firmware — it runs its own mDNS/eSCL/AirScan stack and works fine without cartridges after a Stop/Reset bypass. But I got curious and went deeper.

---

## Setup

- **Device:** Canon PIXMA TS3451 (PCB fully removed)
- **Host:** Windows 11 + WSL2 (Ubuntu 24)
- **Tools:** mitmproxy, flashrom, Raspberry Pi 5, Python 3, Ghidra, binwalk, pycryptodome

---

## Phase 1 — Network Interception (MITM)

### Proxy setup

The printer's web admin interface (`192.168.x.x/rui/index.html`) exposes an HTTP proxy configuration option. I set up:

1. `mitmproxy` running in WSL2
2. A Windows `portproxy` rule forwarding printer traffic to WSL2

This gave full HTTP interception of all printer traffic.

### Canon infrastructure

```
gdlp01.c-wss.com              HTTP/80    Firmware manifest (AES-GCM encrypted)
dtv-p.c-ij.com                HTTP/80    Version check + CA trust store
skyprtr-an13.srv.ygles.com    HTTPS/443  Canon cloud (DigiCert cert, TLS pinned)
```

Traffic to `gdlp01.c-wss.com` and `dtv-p.c-ij.com` is **plain HTTP** — trivial to intercept and modify.

### Version check bypass

The firmware update flow:

1. Printer fetches `http://dtv-p.c-ij.com/sdata/struct01/version.bin` (2 bytes)
2. Compares with local version
3. If remote > local → fetches the manifest

By intercepting and patching the response (`0x08 0x00` → `0xFF 0xFF`), the printer believes an update is available and fetches the manifest.

**mitmproxy addon:**

```python
from mitmproxy import http

class FakeCanonVersion:
    def response(self, flow: http.HTTPFlow):
        if "dtv-p.c-ij.com" in flow.request.pretty_host and "version.bin" in flow.request.path:
            flow.response.content = bytes([0xFF, 0xFF])
            flow.response.headers["Content-Length"] = "2"

        # Save everything from Canon servers
        if any(d in flow.request.pretty_host for d in ["gdlp01.c-wss.com", "c-ij.com"]):
            fname = flow.request.path.split("/")[-1] or "index"
            with open(f"/tmp/canon_{fname}", "wb") as f:
                f.write(flow.response.content)

addons = [FakeCanonVersion()]
```

### Firmware manifest

Full URL of the manifest:
```
http://gdlp01.c-wss.com/rmds/ij/ijd/ijdupdate/a18b7.bin
```

The file is **304 bytes = exactly 19 AES blocks of 16 bytes**.

```
Entropy : 7.31 bits/byte
Blocks  : 19 × 16 bytes (no AES-ECB repetitions)
→ AES-CBC or AES-GCM
```

Manifest hex dump:
```
246ab3ce 885379c2 09f86e9b 7cf7fd28  $j...Sy...n.|..(
c7fe298d a395a6a7 ffa43175 37150959  ..).......1u7..Y
...
defd68bd 8cf777d9 98b67939 e589a898  (last 16 bytes = likely GCM tag)
```

### CA trust store (sdata.bin)

`http://dtv-p.c-ij.com/sdata/struct01/sdata.bin` contains the printer's CA list, decryptable with leecher1337's `dec_sdata` tool.

**20 CAs extracted, 5 already expired:**

| CA | Expiry | Status |
|---|---|---|
| Baltimore CyberTrust Root | May 2025 | **Expired** |
| Equifax Secure CA | 2018 | **Expired** |
| GeoTrust Global CA | 2022 | **Expired** |
| GTE CyberTrust Global Root | 2018 | **Expired** |
| GlobalSign Root CA R2 | 2021 | **Expired** |
| DigiCert Global Root CA | 2031 | Valid |
| Amazon Root CA 1–4 | 2038–2040 | Valid |
| GlobalSign Root CA / R3 / R4 | 2028–2038 | Valid |
| VeriSign Class 3 G2/G5 | 2028–2036 | Valid |
| GTS Root R1/R2/R3/R4 | 2036 | Valid |

`skyprtr-an13.srv.ygles.com` is signed by DigiCert (valid until 2027) → TLS interception blocked.

---

## Phase 2 — Physical Firmware Dump

### Hardware identification

```
Flash chip : Winbond W25Q128.V
Capacity   : 16 MB
Interface  : SPI 3.3V
RAM        : NANYA NT5CC128M8GR (DDR3 128MB, visible on PCB)
SoC        : Canon custom ASIC FSJ0AS018CA (QK2-4000)
             Manufactured in Taiwan, 2204 (Q2 2022)
             Same chip used in: Canon PIXMA TS3450, Canon PIXMA E3640
```

### SPI wiring (Raspberry Pi 5 GPIO)

PCB was fully removed from the printer. Flash chip wired directly to Pi GPIO:

```
SOIC-8 Pin 1 (CS#)   → GPIO 8  (CE0, physical pin 24)
SOIC-8 Pin 2 (MISO)  → GPIO 9  (MISO, physical pin 21)
SOIC-8 Pin 3 (WP#)   → 3.3V
SOIC-8 Pin 4 (GND)   → GND    (physical pin 20)
SOIC-8 Pin 5 (MOSI)  → GPIO 10 (MOSI, physical pin 19)
SOIC-8 Pin 6 (CLK)   → GPIO 11 (SCLK, physical pin 23)
SOIC-8 Pin 7 (HOLD#) → 3.3V
SOIC-8 Pin 8 (VCC)   → 3.3V   (physical pin 1)
```

### Dump

```bash
# Enable SPI on Pi
sudo raspi-config nonint do_spi 0

# Install flashrom
sudo apt install flashrom -y

# Detect chip
sudo flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=4000
# Found Winbond flash chip "W25Q128.V" (16384 kB, SPI)

# Dump twice and verify integrity
sudo flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=4000 -r dump1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=4000 -r dump2.bin
md5sum dump1.bin dump2.bin
# 14c99631cf1d3b04f00d0d53f8f79f91  dump1.bin
# 14c99631cf1d3b04f00d0d53f8f79f91  dump2.bin
```

Identical MD5 → clean dump.

**Firmware hashes:**
```
MD5    : 14c99631cf1d3b04f00d0d53f8f79f91
Size   : 16777216 bytes (16 MB)
Version: V00.15.RC1.JAPAN-CANON
```

---

## Phase 3 — Firmware Analysis

### Partition map (16 MB)

Entropy analysis (64KB chunks):

| Offset | Size | Entropy | Content |
|--------|------|---------|---------|
| 0x000000 | 256 KB | ~2.4 | **ARM32 bootloader (plaintext)** |
| 0x040000 | ~1.7 MB | 0.00 | Empty flash (0xFF) |
| 0x220000 | 128 KB | ~4.6 | Config / certificates |
| 0x2E0000 | ~1.8 MB | ~8.0 | **DryOS firmware (zlib + AES-GCM)** |
| 0x560000 | ~4.5 MB | ~8.0 | Firmware backup image |
| 0xBA0000 | ~2.3 MB | ~8.0 | Third firmware partition |
| 0xF00000 | ~1 MB | mixed | **NVRAM / persistent config** |

### Bootloader (0x000000, plaintext ARM32)

The bootloader is unencrypted. It contains Canon's RSA public keys and implements a full secure boot chain:

```
Strings found:
  V00.15.RC1.JAPAN-CANON    ← exact firmware version
  cSt.>;w7y8)Ug%T[          ← 16-byte AES key candidate (unconfirmed)

RSA functions:
  CLS_ALLOCATE_RSA_PUBLIC_KEY
  FLH_AssetLoadRSAPublicKey
  CLS_HashVerifyRecoverPkcs1

Secure boot chain:
  SoC ROM (immutable)
    → verifies bootloader RSA signature
      → bootloader verifies firmware signature
        → firmware executes
```

Modifying the bootloader without Canon's private key = brick.

### Decompressed firmware blobs

The high-entropy zones contain **nested zlib blobs**, identified by magic byte scan (`78 9c`, `78 da`):

```bash
# Zone 0x2E0000 contains 3 valid zlib streams:
+0x06004  → zlib → 1024 KB  [blob0: ARM Thumb code]
+0x95c9c  → zlib → 1024 KB  [blob1: network/crypto stack]
+0x142288 → zlib → 1024 KB  [blob2: web interface / HTTP]
```

**blob1 — network stack:**

```
Full firmware update URL:
  http://gdlp01.c-wss.com/rmds/ij/ijd/ijdupdate/a18b7.bin

User-Agent: IP Client/1.0.0.0

Crypto library: MatrixSSL / RSA Security BSAFE
Key functions found:
  flpsul_create_gcm_giv_key_and_state  ← AES-GCM with generated IV
  CLS_EncryptAuthInitDeterministic
  CLS_AssetAllocate
  CLS_AssetLoadValue
  tagLen == 16
  IV_prefixlen == 4 || IV_prefixlen == 6
  keylen == 16 || keylen == 24 || keylen == 32
```

**blob2 — web interface & OS:**

```
Full embedded HTTP server
Admin UI at /rui/ (JavaScript)
Firmware update endpoints: firm_update.cgi, get_job_status.cgi
Full mDNS/DNS-SD stack
eSCL/AirScan support (driverless scanning over network)
NS_FLAG_NETUPDATE=enable
R_CR_decrypt_init / R_CR_decrypt_update / R_CR_decrypt_final
  → "HMAC MD5 err", "HMAC SHA1 err", "AES Keywrap err"
AES S-box found at blob2+0x8a3db
```

### NVRAM (0xF00000)

Persistent config stored in plaintext, including WiFi credentials (SSID + password stored as cleartext strings in flash).

### Why the AES key is unreachable via static analysis

The AES-GCM key for the manifest is managed by a **software Asset Store** (software HSM):

```
CLS_AssetAllocate          → allocates a protected memory slot
CLS_AssetLoadValue         → loads key material into protected slot
flpsul_create_gcm_giv_key  → initializes AES-GCM with generated IV
```

The key **never exists as plaintext on the flash**. It is derived at runtime using Canon's RSA certificates from the bootloader. Static analysis hits a hard wall here.

---

## The Open Question — Help Needed

### AES-GCM manifest structure

```
Total size  : 304 bytes
= 19 × 16-byte AES blocks

Possible structure A (nonce 12 bytes):
  [nonce 12B][ciphertext 276B][tag 16B]

Possible structure B (nonce 4 bytes, matching IV_prefixlen==4):
  [nonce 4B][ciphertext 284B][tag 16B]

Possible structure C (nonce 6 bytes, matching IV_prefixlen==6):
  [nonce 6B][ciphertext 282B][tag 16B]
```

### What I need help with

1. **MatrixSSL Asset Store key derivation** — does anyone know how `flpsul_create_gcm_giv_key_and_state` derives its key from the Asset Store in MatrixSSL/BSAFE? The source is partially open — maybe the derivation scheme is documented or reversible.

2. **UART debug pads** — the PCB has unpopulated pad groups. If anyone has done UART work on Canon PIXMA TS3400 series, I'd love to compare notes on baud rate and pinout.

3. **Buffer overflow in NVRAM** — since NVRAM is unsigned, oversized WiFi credentials might trigger a stack overflow in the credential parsing code. Haven't tested yet (waiting for CH341A clip to arrive for safe reflashing).

---

## Summary

| Category | Finding |
|----------|---------|
| Network | 3 Canon domains, 2 in plaintext HTTP |
| Manifest | AES-GCM, identifier `a18b7`, full URL recovered |
| Trust store | 20 CAs extracted, 5 expired |
| Flash | Winbond W25Q128 16MB, clean dump |
| Firmware | 3 partitions + bootloader, 3 zlib blobs decompressed |
| Crypto | MatrixSSL/BSAFE, AES-GCM, runtime Asset Store |
| NVRAM | WiFi credentials in cleartext |
| Version | V00.15.RC1.JAPAN-CANON |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `mitmproxy` | Network interception |
| `flashrom` | SPI dump/flash |
| `Raspberry Pi 5` | SPI programmer via GPIO |
| `Python 3` + `pycryptodome` | Crypto analysis |
| `Ghidra` | ARM reverse engineering |
| `binwalk` | Firmware analysis |
| `dec_sdata` (leecher1337) | Trust store decryption |
| `sane-airscan` | Driverless scan test |

---

## References

- Contextis — "Hacking Canon PIXMA Printers: Doomed Encryption" (2014)
- Synacktiv — "Treasure Chest Party Quest: From Doom to Exploit" (2020)
- leecher1337/pixma — Canon PIXMA firmware tools (GitHub)
- synacktiv/canon-tools — Canon firmware decryption tools (GitHub)

---

*Research conducted on personally owned hardware. Sensitive device-specific identifiers have been anonymized. No Canon servers were accessed without authorization — all traffic was generated by the printer itself on the local network.*
