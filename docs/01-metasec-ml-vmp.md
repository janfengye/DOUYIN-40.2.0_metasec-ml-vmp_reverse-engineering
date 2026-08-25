# 01 — The `metasec_ml` VMP (static map)

`libmetasec_ml.so` is ByteDance's metasec/mssdk request signer — the native library that produces the
`X-Argus` / `X-Gorgon` / `X-Ladon` / `X-Khronos` anti-abuse headers. The signing algorithm is wrapped in a
custom bytecode VM (a "VMP"). This document is the recovered, re-verified map of that VM. Method: handler-table
devirtualization (52pojie thread-2123217). Verifier: [../tools/verify_metasec_ml.py](../tools/verify_metasec_ml.py).

## File identity

| Property | Value |
|---|---|
| Machine | AArch64 (NDK r25c, stripped) |
| Size | 4,525,552 bytes |
| SHA-256 | `7ed8596e2c9ed6422293d1a1522a2d74fc7f5145e2170256eb0ba2d6ed46300b` |
| Exports | exactly **1** — `JNI_OnLoad` (natives registered dynamically via hidden `RegisterNatives`) |
| `.text` | `0x176500 … 0x3c5ff4` (~2.4 MB) |

**Protection fingerprint:** `.init_array` is zero in the file and filled by **16982 `R_AARCH64_RELATIVE`**
relocations at load (these also fill the handler table); ~599k instructions at ~98% linear coverage with
**5231 indirect `br`** (control-flow flattening); JNI strings are encrypted (`.rodata` holds only libc/C++
strings) and recovered via native op `0x1000001` (see [02](02-offline-signing.md)); `JNI_OnLoad` uses
`bl next; add x1,x0,#off; br x1` trampolines plus `svc #0` gates.

## The interpreter — table-based, direct-threaded

`vm_run(x0, x1)` at **`0x2e7fe8`**; the dispatch core at **`0x2e8014`** disassembles to:

```asm
0x002e7fe8: sub  sp, sp, #0x70            ; vm_run prologue
0x002e8008: ldr  x9, [x0]                 ; bytecode base = *x0
0x002e800c: mov  x23, x1                  ; x23 = &VM-PC
...
0x002e8014: adrp x25, #0x3e1000
0x002e8018: add  x25, x25, #0xe58         ; x25 = HANDLER TABLE @ 0x3e1e58
0x002e8028: str  wzr, [x23, #0xc]!        ; VM-PC (u32 index) = 0
; per instruction (threaded):
;   idx = (*x23)++ ; instr = bytecode_base + idx*0x30
;   op  = *(u16)instr ; handler = table[op] ; br handler
0x002e8034: ldr  x10, [x25, x10, lsl #3]  ; handler = table[op]
```

The instruction stride is **48 bytes** (`smaddl x8, w9, #0x30, x10` in the fetch). Each handler decodes its
operands and jumps straight to the next handler — no central loop — which is why the CFG is flattened.

### Register model

| Reg | Role |
|---|---|
| `x25` | handler-table base (`0x3e1e58`) |
| `x20` | pointer to VM bytecode base |
| `x23` | pointer to VM-PC (u32 instruction index) |
| `x8` | current instruction ptr = `*x20 + idx*0x30` |
| `x24` | int/pointer register file (8-byte slots) |
| `x26` | float register file (4-byte slots) |
| `x27` | double register file (8-byte slots) |
| `instr+8/9/10` | packed 8-bit operand register indices (some ops read `+0xa` as a u16 imm) |

### Instruction format

48 bytes fixed: `[+0]` = u16 opcode, `[+8..+10]` = operand register indices.

## Handler table @ `0x3e1e58` — verified

The table lives in `.data.rel.ro`. `verify_metasec_ml.py` confirms, against this exact binary:

```
0x3e1e58 in section .data.rel.ro
relocs in claimed table [1133 slots]: 1133
addend min/max: 0x2e5f10 0x305acc   uniq: 1132
within .text: 1133 / 1133
within claim 0x2e5f10..0x305acc: 1133 / 1133
```

So **1133 slots → 1132 unique handlers**, every target inside `.text` and inside the stated code window. Handler
bodies are 36–348 bytes (median ~108).

### Opcode taxonomy (over the 1132 handlers)

| Feature | Count | Meaning |
|---|---|---|
| load | 1132 | every op reads operands |
| arith | 1129 | add/sub/mul/and/orr/eor/shift/div |
| store | 675 | writes a register file |
| helper-call | 499 | delegates to a native primitive (`bl`) |
| **vm-branch** | **138** | writes VM-PC `[x23]` from an operand (jumps/returns) |
| cond | 56 | `b.cc` / `cset` / `csel` |
| fp | 40 | `fadd`/`fsub`/`fmul`/`fcmp`… |
| convert | 18 | `scvtf`/`fcvtzs`/`fcvt` |

Decoded examples: `0x00` zero-freg · `0x03` load shifted-imm→int · `0x04` `fcvtzs` · `0x02/0x05` double-compare ·
`0x01` 3-operand helper call · `0xbd` `VMPC = int_reg[op]` + return (computed jump/leave).

### Helper primitives — the actual compute

The opcodes themselves are thin; the arithmetic muscle lives in **464 unique `bl` helper targets**, dominated by
a few:

| Helper | # opcodes using it |
|---|---|
| `0x36c9e0` | 672 |
| `0x337090` | 335 |
| `0x36bf18` | 335 |
| `0x358e14` | 33 |

## Emulation — proven

`emulate_vm.py` (in the original workset) maps the PT_LOAD segments, applies the 16982 RELATIVE relocations
(which fill the handler table), sets `x0`/`x1`/`sp`, and runs the **real** interpreter over crafted bytecode
under Unicorn. Verified: four `0x03` (load shifted-imm) opcodes produced
`int_reg[5..8] = {0x12340000, 0x56780000, 0x10000, 0xffffffffabcd0000}` — byte-exact against
`sign_extend32(imm << 16)`, executing the genuine VMP handlers. This establishes a working offline VM engine;
it is *not* a full devirtualization of the signing bytecode (that bytecode is runtime-only, with no static
xrefs). For producing signatures, whole-library emulation ([02](02-offline-signing.md)) is the practical path.
