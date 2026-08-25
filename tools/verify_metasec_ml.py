#!/usr/bin/env python3
"""
verify_metasec_ml.py — ground-truth the Douyin metasec_ml VMP map (docs/01).

Confirms the opcode->handler table @0x3e1e58 (1133 reloc-filled slots, all addends in .text within
0x2e5f10..0x305acc) and disassembles the interpreter core (0x2e8014) + vm_run (0x2e7fe8).

Usage:  python verify_metasec_ml.py [path/to/libmetasec_ml.so]
Deps:   pip install lief capstone
You supply the .so yourself (not redistributed here).
"""
import sys
import lief, capstone

P = sys.argv[1] if len(sys.argv) > 1 else 'so/libmetasec_ml.so'
b = lief.parse(P)

def H(x):
    try: return hex(x)
    except: return str(x)

print("machine:", b.header.machine_type)
exps = [getattr(e, 'name', e) for e in b.exported_functions]
print("exports:", len(exps), exps[:6])

text_lo = text_hi = None
for s in b.sections:
    if s.name == '.text':
        text_lo, text_hi = s.virtual_address, s.virtual_address + s.size
print("text:", H(text_lo), H(text_hi))

cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

def vb(va, n):
    try: return bytes(b.get_content_from_virtual_address(va, n))
    except Exception: return None

def dis(va, n, label):
    print(f"== {label} @ {H(va)} ==")
    c = vb(va, n * 4)
    if not c:
        print("  <none>"); return
    for i in cs.disasm(c, va):
        print(f"  {i.address:#010x}: {i.mnemonic:8} {i.op_str}")

# handler table @0x3e1e58 — claim: 1133 slots, addends in .text within 0x2e5f10..0x305acc
TBL, NS = 0x3e1e58, 1133
TSZ = NS * 8
for s in b.sections:
    if s.virtual_address <= TBL < s.virtual_address + s.size:
        print(f"0x3e1e58 in section {s.name}")
relocs = list(b.relocations)
intbl = [r for r in relocs if getattr(r, 'address', -1) is not None and TBL <= getattr(r, 'address', -1) < TBL + TSZ]
print(f"relocs in claimed table [{NS} slots]:", len(intbl))
if intbl:
    add = sorted(getattr(r, 'addend', 0) for r in intbl)
    print("addend min/max:", H(add[0]), H(add[-1]), "uniq:", len(set(add)))
    if text_lo:
        print("within .text:", sum(text_lo <= x < text_hi for x in add), "/", len(add))
    print("within claim 0x2e5f10..0x305acc:", sum(0x2e5f10 <= x <= 0x305acc for x in add), "/", len(add))

dis(0x2e7fe8, 10, "vm_run 0x2e7fe8")
dis(0x2e8014, 14, "interp core 0x2e8014 (adrp x25,#0x3e1000; ldr x10,[x25,x10,lsl#3]; br x10)")
