# harness — offline `metasec_ml` signing PoC

unidbg-based harness that runs `libmetasec_ml.so` on a desktop JVM and drives the op sequence from
[../docs/02-offline-signing.md](../docs/02-offline-signing.md). Adapted from the public `fqnovel-unidbg` /
`hongguo unidbg-sign` template (same metasec SDK).

## Prerequisites

- JDK 21 (Temurin) + Maven 3.9+
- Your **own** `libmetasec_ml.so` + `libc++_shared.so` (from the APK) in `harness/so/`
- The 244-byte metasec license (redacted here) pasted into `DouyinMetasecSign.java` — see the `LICENSE` field
  comment for where it lives in the app (`SecApiImpl`, `classes14.dex`).

`so/` and `capture/` are git-ignored; nothing proprietary is committed.

## Build & run

```bash
cd harness
mvn -q clean package
java -Dinit=1 -DappID=1128 -jar target/unidbg-douyin-1.0-jar-with-dependencies.jar   # init + get handle + frameSign
java -Ddecrypt=1           -jar target/unidbg-douyin-1.0-jar-with-dependencies.jar   # string-decrypt op 0x1000001
```

## Expected

`-Dinit=1` → `JNI_OnLoad OK`, `init returned = true`, `session handle = 314318848`, and a `frameSign` block
(`signinfo` / `signvalue` / `signversion`).

## Caveat

The emitted signature is **well-formed but unvalidated** — not confirmed accepted by any server, and this repo
does not build any API client on top of it. Analysis PoC only. See the caveat section of docs/02. If Maven fails
to find `com.github.unidbg.Module`, apply the POM/jitpack fix noted in docs/02.
