# Canon PIXMA TS3451 — Firmware Research Write-up

**Date:** July 2026  
**Author:** TheFrenchGuy  
**Status:** ✅ Complete — manifest and OTA firmware fully decrypted  
**Firmware version:** V00.15.RC1.JAPAN-CANON / 1.040

---

## TL;DR

First documented firmware analysis of the Canon PIXMA TS3451 (2020+ series). Using a Raspberry Pi 5 GPIO as an SPI programmer, I dumped the full 16MB flash (Winbond W25Q128). Found 20 decompressed zlib firmware blobs across 3 partitions. The firmware update manifest was AES-128-CBC encrypted — key and IV recovered by community member **Wintermute** via blob disassembly. Full OTA firmware (`A18B7V1040AN.bin`) subsequently downloaded and decrypted.

**What's new:** All public Canon PIXMA firmware research (Synacktiv, Contextis, leecher1337) targets 2010-2015 models. The TS3400 series had never been documented publicly.

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
gdlp01.c-wss.com              HTTP/80    Firmware manifest (AES-128-CBC encrypted)
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

        if any(d in flow.request.pretty_host for d in ["gdlp01.c-wss.com", "c-ij.com"]):
            fname = flow.request.path.split("/")[-1] or "index"
            with open(f"/tmp/canon_{fname}", "wb") as f:
                f.write(flow.response.content)

addons = [FakeCanonVersion()]
```

### Firmware manifest — SOLVED ✅

Full URL of the manifest:
```
http://gdlp01.c-wss.com/rmds/ij/ijd/ijdupdate/a18b7.bin
```

The manifest is **AES-128-CBC encrypted** (not AES-GCM as initially suspected).

**Decryption (credit: Wintermute):**
```bash
openssl enc -d -aes-128-cbc \
  -K e3b7ab92ea3d18ce1be4b39a72d11204 \
  -iv 44230b7adada0b1a569bfacdb5400245 \
  -in a18b7.bin \
  -out manifest_decrypted.xml
```

**Decrypted manifest:**
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<update_info>
  <Dummy1>Dummy1</Dummy1>
  <Dummy2>Dummy2</Dummy2>
  <Dummy3>Dummy3</Dummy3>
  <version>1.040</version>
  <url>http://pdisp01.c-wss.com/gdl/WWUFORedirectTarget.do?id=MDQwMDAwNzg2MzAx</url>
  <size>7230976</size>
</update_info>
```

**Key/IV generator functions** located at `0xb88b4` and `0xb8702` in the firmware blobs (streams at offsets `0x002E6004`, `0x00375C9C`, `0x00422288`, `0x00499D70`).

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
sudo raspi-config nonint do_spi 0
sudo apt install flashrom -y
sudo flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=4000
# Found Winbond flash chip "W25Q128.V" (16384 kB, SPI)

sudo flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=4000 -r dump1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=4000 -r dump2.bin
md5sum dump1.bin dump2.bin
# 14c99631cf1d3b04f00d0d53f8f79f91  (both identical)
```

**Firmware hashes:**
```
MD5    : 14c99631cf1d3b04f00d0d53f8f79f91
Size   : 16777216 bytes (16 MB)
Version: V00.15.RC1.JAPAN-CANON
```

---

## Phase 3 — Firmware Analysis

### Partition map (16 MB)

| Offset | Size | Entropy | Content |
|--------|------|---------|---------|
| 0x000000 | 256 KB | ~2.4 | **ARM32 bootloader (plaintext)** |
| 0x040000 | ~1.7 MB | 0.00 | Empty flash (0xFF) |
| 0x220000 | 128 KB | ~4.6 | Config / certificates |
| 0x2E0000 | ~1.8 MB | ~8.0 | **DryOS firmware (zlib + AES-CBC)** |
| 0x560000 | ~4.5 MB | ~8.0 | Firmware backup partition |
| 0xBA0000 | ~2.3 MB | ~8.0 | Third firmware partition |
| 0xF00000 | ~1 MB | mixed | **NVRAM / persistent config (plaintext)** |

### Decompressed firmware blobs — 20 total

Full zlib scan across all partitions found **20 unique decompressible streams**:

**Main partition (0x2E0000) — 4 blobs:**
```
0x002E6004  → 1024 KB  ARM Thumb code
0x00375C9C  → 1024 KB  Network/crypto stack (MatrixSSL/BSAFE)
0x00422288  → 1024 KB  Web interface / HTTP server
0x00499D70  →  ~100 KB mDNS/Bonjour + cert manager
```

**Backup partition (0x560000) — 9 blobs:**
```
Print-job-status XML, MIME decoder (scan-to-email),
scan subsystem code, UI glyph/bitmap atlas,
local-UI cert-management templates,
second MatrixSSL blob at 0x8b1044 (matrixsslApi.c)
```

**Third partition (0xBA0000) — 6 blobs:**
```
ARM code blobs, DryOS subsystem debug strings,
PNG image assets, LCD touchscreen UI
(message tables + JS state machine + CSS)
```

### Key findings in blobs

```
firmware update URL    : http://gdlp01.c-wss.com/rmds/ij/ijd/ijdupdate/a18b7.bin
User-Agent             : IP Client/1.0.0.0
Crypto library         : MatrixSSL / RSA Security BSAFE
SNMP                   : net-snmp 5.7.2 (v1 only, community: public)
Web interface accounts : canon_admin / canon_user (no default password)
eSCL/AirScan           : fully implemented (driverless scanning)
```

### NVRAM (0xF00000, plaintext)

WiFi credentials stored in cleartext. Firmware version string at offset +0x0845A5.

---

## Phase 4 — OTA Firmware — SOLVED ✅

### Download and decrypt

```bash
# Download official Canon OTA firmware
wget -L "http://pdisp01.c-wss.com/gdl/WWUFORedirectTarget.do?id=MDQwMDAwNzg2MzAx" \
  -O A18B7V1040AN.bin
# → redirects to http://gdlp01.c-wss.com/gds/3/0400007863/01/A18B7V1040AN.bin
# Size: 7,230,976 bytes

# Decrypt (credit: Wintermute)
openssl enc -d -aes-128-cbc \
  -K fa935576d14688c358574f225348151e \
  -iv 7954d086f70daf214d3bf290d350ce5c \
  -in A18B7V1040AN.bin \
  -out A18B7V1040AN.ijsb
```

### IJSB format structure

The decrypted file uses Canon's proprietary **IJSB (IJ Software Bundle)** format:

```
Magic    : IJSB
Metadata : <metadata version="1.0.0"><model>A18B7</model><version>1.040</version></metadata>

Section 0: IJFIRM_BEGIN
Section 1:  28 KB  — SROM:1:1 (bootloader stub)
Section 2:   0 KB  — empty
Section 3: 4557 KB — main firmware image (contains zlib blobs)
Section 4: 2399 KB — backup firmware image
Section 5:  75 KB  — supplemental data
           IJFIRM_END
```

**Key generator locations** (credit: Wintermute):
```
Manifest key/IV gen : blob offsets 0xb88b4 and 0xb8702
OTA firmware key/IV gen : blob offset 0xB884C and 0xB869A
Decrypting code     : blob offset 0x3b592 (manifest), 0x4CD3C (OTA)
```

---

## Summary

| Category | Finding |
|----------|---------|
| Network | 3 Canon domains, 2 in plaintext HTTP |
| Manifest | **AES-128-CBC, fully decrypted** ✅ |
| OTA firmware | **Downloaded and decrypted** ✅ |
| Trust store | 20 CAs extracted, 5 expired |
| Flash | Winbond W25Q128 16MB, clean dump |
| Firmware | 20 zlib blobs across 3 partitions |
| Crypto | MatrixSSL/BSAFE, AES-128-CBC |
| NVRAM | WiFi credentials in cleartext |
| IJSB format | 5-section bundle, documented |
| Version | V00.15.RC1.JAPAN-CANON / 1.040 |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `mitmproxy` | Network interception |
| `flashrom` | SPI dump/flash |
| `Raspberry Pi 5` | SPI programmer via GPIO |
| `Python 3` + `pycryptodome` | Crypto analysis |
| `Ghidra` | ARM reverse engineering |
| `openssl` | Firmware decryption |
| `dec_sdata` (leecher1337) | Trust store decryption |
| `sane-airscan` | Driverless scan test |

---

## Credits

- **Wintermute** — recovered AES-128-CBC keys for both manifest and OTA firmware. This research wouldn't be complete without his contribution.

---

## References

- Contextis — "Hacking Canon PIXMA Printers: Doomed Encryption" (2014)
- Synacktiv — "Treasure Chest Party Quest: From Doom to Exploit" (2020)
- leecher1337/pixma — Canon PIXMA firmware tools (GitHub)
- synacktiv/canon-tools — Canon firmware decryption tools (GitHub)
- CHDK Wiki — DryOS PIXMA Printer Shell

---

*Research conducted on personally owned hardware. Sensitive device-specific identifiers have been anonymized. No Canon servers were accessed without authorization — all traffic was generated by the printer itself on the local network.*
