# 02 — Offline request-signing (unidbg PoC)

**Goal:** run `libmetasec_ml.so` on a desktop JVM — no device, no network — drive its init contract, and get
`frameSign` to emit a signature. **Result:** it works, confirmed by execution. Harness:
[../harness/DouyinMetasecSign.java](../harness/src/main/java/com/dy/sign/DouyinMetasecSign.java) (unidbg 0.9.9,
JDK 21), adapted from the public `fqnovel-unidbg` / `hongguo unidbg-sign` template — same metasec SDK.

## Java SDK surface (jadx, `classes55.dex`)

Public wrappers `com.bytedance.mobsec.metasec.ml.{MS,MSB,MSManager,MSManagerUtils}` sit over an obfuscated
`ms.bd.c.*` (149 classes). All native calls funnel through one dispatcher (registered at `module+0x29b2b4`):

```java
ms.bd.c.m.a(int op, int op2, long handle, String s, Object o)   // native dispatcher
ms.bd.c.m.c(...)                                                 // 2nd native (switch init)
// native → Java callback for env/device data:
com.bytedance.mobsec.metasec.ml.MS.b(op, ...) -> d3.LIZ(...)
```

### Recovered op map

| op (hex / dec) | meaning |
|---|---|
| `0x1000001` / 16777217 | **string-decrypt primitive** `a(op,0,0,"keyhex",byte[]) → plaintext` |
| `0x1000003` / 16777219 | native sub-init with `Context` |
| `0x100000c` / 16777228 | switch-driven init (native `c`) |
| `0x2000001` / 33554433 | **report** (feeds url + `x-ss-stub`) |
| `0x2000002/3` | set device id / install id |
| `0x200000a` / 33554442 | **frameSign** → `String[]` |
| `0x4000001` / 67108865 | **init** (config JSON) → `Boolean` |
| `0x4000002` / 67108866 | get session handle → `Long` |

## Init parameters (from `SecApiImpl`, `classes14.dex`)

- **appID `1128`** (Douyin `aweme` aid; the license is bound to it — other aids return null).
- **hardcoded 244-byte metasec license** (redacted in this repo — see the `LICENSE` field comment for its home).
- config index 4 (`s4.LIZ`) = `decrypt("bebb7f", …)` = an SDK version string.

The init config is a **positional JSON array** (`u2.LIZ()`); only `appID` (idx0), the SDK-version string (idx4),
`deviceID` (idx6) and `installID` (idx8) are meaningful — the rest are constant defaults.

## Drive sequence & observed output

```
op 0x1000003 (context)  →  op 0x100000c (switch)  →  op 0x4000001 (config) = TRUE
op 0x4000002  → handle = 314318848
op 0x2000002/3 (device/install id)  →  op 0x2000001 (report)  →  op 0x200000a (frameSign)
```

```
[+] JNI_OnLoad OK. base=0x122c0000
[*] init returned = true
[+] INIT OK — session handle = 314318848
===SIGN_START===
  frametype   2
  lid         <int>
  signinfo    <192 hex chars>
  signvalue   <SHA-256>
  signversion 1.0
===SIGN_END===
```

The license **validates entirely offline** (no network). A handful of JNI up-calls are stubbed for the native
side (`getPackageName`, `getFilesDir`/`getAbsolutePath`, timestamps, the `MS.b(op)` env callback); the metasec
state files (`.msdata` etc.) are created on demand through an `IOResolver` and are not required for `frameSign`.

## String-obfuscation fully broken (op `0x1000001`)

Feeding the harvested `("keyhex", seed[])` pairs to op `0x1000001` under unidbg (`-Ddecrypt=1`) recovers plaintext:

```
b63691 -> "content"      6dd7f7 -> "/proc/%d/cmdline"     a9e465 -> "/sys/devices/system/cpu/"     fd8956 -> "{}"
```

(Worth noting: the *same* primitive in the sibling `metasec_ov` build yields garbage unless the key/seed
extraction is corrected — a reminder that "the op exists" and "the op decodes correctly for this build" are two
different claims. For `_ml` it decodes cleanly.) The decrypted paths also expose the anti-debug / anti-emu probes
(parent cmdline, CPU topology) that the env callbacks must satisfy.

## Honest limits

`frameSign` proves the crypto engine + init + license all run offline and emit a well-formed signature. It does
**not** prove that a full HTTP `X-Argus`/`X-Gorgon` header built from this session will be **accepted** by
Douyin's servers — those headers are assembled on the Cronet/TTNet path from the same `handle`, and acceptance
is further gated on real, mutually-consistent `device_id`/`install_id` (consistent with the host app's
`device_register`). Wiring one real header and validating it against a device capture is the remaining step and
is intentionally not done here.

## Build note (POM trap)

jitpack serves a broken unidbg *parent* POM (packaging `jar`, not `pom`), which silently drops the transitive
`unidbg-api`/`unicorn`/`jna` deps (`class file for com.github.unidbg.Module not found`). Fix: remove the jitpack
`<repository>` and `rm -rf ~/.m2/repository/com/github/zhkl0228`, then let Maven Central resolve
`com.github.zhkl0228:unidbg-android:0.9.9` (valid POMs).
