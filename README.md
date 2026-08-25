# Reverse-Engineering ByteDance `metasec_ml` — the request-signing VMP in Douyin 40.2.0

> **Security research / educational.** Static + emulated analysis of a shipping Android library. **No
> proprietary ByteDance binaries are redistributed** (you supply `libmetasec_ml.so` from your own copy of the
> APK). The metasec license is redacted. **Scope is limited to request signing** — content-DRM / media
> decryption is deliberately out of scope. See [DISCLAIMER.md](DISCLAIMER.md).

**Target:** `com.ss.android.ugc.aweme` v40.2.0, arm64-v8a
**Core artifact:** `libmetasec_ml.so` — ByteDance's metasec/mssdk request signer (the engine behind
`X-Argus` / `X-Gorgon` / `X-Ladon` / `X-Khronos`, the anti-abuse signatures that gate most Douyin APIs)

---

## Abstract

This repo documents a reverse-engineering pass over ByteDance's `metasec_ml` protection library as shipped in
Douyin 40.2.0, along two axes:

1. **A verified static map of the VMP.** `metasec_ml` is a table-based, direct-threaded bytecode interpreter
   (a "VMP") wrapping the signing algorithm. Its interpreter core, 1133-entry handler table, 48-byte
   instruction format, register model, and opcode taxonomy are recovered and re-confirmed against the binary.
2. **A working, device-free signing harness.** Running the whole library under [unidbg](https://github.com/zhkl0228/unidbg)
   on a desktop JVM, the engine loads, initializes against its real (app-bound) license, and `frameSign` emits a
   structurally-correct signature — **confirmed by execution**, not inference.

Every concrete claim below was re-run against the binary while writing this, using the scripts in
[`tools/`](tools/) and the harness in [`harness/`](harness/). Where a result is *not* fully proven (e.g. server
acceptance of the header), that is stated plainly rather than glossed.

<details>
<summary><b>Tóm tắt (Tiếng Việt)</b></summary>

Kho này ghi lại một lượt dịch ngược thư viện bảo vệ `metasec_ml` của ByteDance trong Douyin 40.2.0, theo 2 trục:

1. **Bản đồ tĩnh VMP đã kiểm chứng.** `metasec_ml` là một máy ảo thông dịch bytecode dạng bảng, direct-threaded
   ("VMP") bọc thuật toán ký. Lõi thông dịch, bảng 1133 handler, định dạng lệnh 48 byte, mô hình thanh ghi và
   phân loại opcode đều được khôi phục và **kiểm chứng lại trên binary**.
2. **Harness ký không cần thiết bị.** Chạy toàn bộ thư viện bằng unidbg trên JVM desktop: engine nạp được, init
   với license thật (gắn theo app), và `frameSign` sinh chữ ký đúng cấu trúc — **xác nhận bằng thực thi**.

Mọi khẳng định đều được chạy lại trên binary khi viết, bằng script trong `tools/` và harness trong `harness/`.
Chỗ nào chưa chứng minh đầy đủ (vd server có chấp nhận header hay không) thì nói rõ, không tô hồng.
**Phạm vi chỉ là ký request** — phần giải mã nội dung/DRM cố ý để ngoài phạm vi.

</details>

---

## What is verified (re-run against the binary)

`libmetasec_ml.so` — AArch64, **4,525,552 bytes**, SHA-256
`7ed8596e2c9ed6422293d1a1522a2d74fc7f5145e2170256eb0ba2d6ed46300b`, exactly **1 export** (`JNI_OnLoad`).

**VMP static map** — see [docs/01](docs/01-metasec-ml-vmp.md):

| Element | Value | Check |
|---|---|---|
| Interpreter `vm_run` | `0x2e7fe8` | disasm |
| Dispatch core | `0x2e8014` (`adrp x25,#0x3e1000; add x25,#0xe58` → `ldr x10,[x25,x10,lsl#3]; br x10`) | disasm |
| Handler table | `0x3e1e58` in `.data.rel.ro` | **1133 RELATIVE relocs**, 1132 unique addends, **all** in `.text`, all within `0x2e5f10..0x305acc` |
| Instruction size | **48 bytes** (`smaddl x8, w9, #0x30, x10`) | disasm |
| Register model | `x25`=table, `x20`=bytecode, `x23`=&PC, `x24/x26/x27`=int/float/double reg-files | disasm |
| Opcodes | 1132 handlers; 138 VM-branch, 499 helper-call, 464 helper primitives | classification |

**Offline signing** — see [docs/02](docs/02-offline-signing.md) — proven **by execution**:

```
[+] JNI_OnLoad OK. base=0x122c0000
[*] driving init op 0x4000001 (appID=1128 …)
[*] init returned = true
[+] INIT OK — session handle = 314318848
===SIGN_START===
  frametype 2 · lid … · signinfo <192 hex> · signvalue <SHA-256> · signversion 1.0
===SIGN_END===
```

The **string-obfuscation** is also fully broken via native op `0x1000001` (unlike some sibling builds where the
same op yields garbage): e.g. `6dd7f7 → "/proc/%d/cmdline"`, `a9e465 → "/sys/devices/system/cpu/"`,
`b63691 → "content"`.

## Honest limits

- `frameSign` proves the **engine + init + license** all run offline and emit a well-formed signature. It does
  **not** prove Douyin's servers *accept* a full `X-Argus`/`X-Gorgon` HTTP header — those are assembled on the
  Cronet/TTNet path from the same session `handle`, and acceptance is additionally gated on real, mutually
  consistent `device_id` / `install_id`. Wiring and validating one header against a device capture is future
  work.
- A **full devirtualization** of the signing bytecode is *not* claimed. The VM is mapped and proven emulatable
  (a Unicorn run executes real handlers byte-exact), but the signing bytecode is a runtime structure with no
  static xrefs; whole-library emulation (the harness) is the practical path to signatures.

## Reproducing

Supply your **own** `libmetasec_ml.so` + `libc++_shared.so` (this repo ships no binaries).

```bash
python tools/verify_metasec_ml.py path/to/libmetasec_ml.so     # confirms the VMP map

cd harness            # JDK 21 + Maven; unidbg 0.9.9
# drop your so/ + paste your license into DouyinMetasecSign.java
mvn -q clean package
java -Dinit=1 -DappID=1128 -jar target/unidbg-douyin-1.0-jar-with-dependencies.jar
java -Ddecrypt=1          -jar target/unidbg-douyin-1.0-jar-with-dependencies.jar   # string-decrypt op 0x1000001
```

## Credits / prior art

- **VMP devirtualization method:** 52pojie thread-2123217 (handler-table recovery).
- **unidbg harness:** adapted from the public `zero199901/fqnovel-unidbg` and the `hongguo` `unidbg-sign`
  template — same metasec SDK family (`ms.bd.c.*` / `com.bytedance.mobsec.metasec.ml`).
- **unidbg** by zhkl0228.

The original contribution here is the *verified* static VMP map for this build, the recovered op map, and the
end-to-end offline init+frameSign for Douyin — with each claim checked against the binary.

## Layout

```
docs/     the paper: VMP map + offline signing
tools/    verify_metasec_ml.py — read-only lief+capstone verifier
harness/  unidbg offline-sign PoC (Java + pom) — license redacted, DRM-free
```
