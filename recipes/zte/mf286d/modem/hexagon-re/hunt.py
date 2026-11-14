# Ghidra post-script (PyGhidra) — AMSS hunt: UIM IDL table, ISD-R xrefs, F3 log sites
# Run: analyzeHeadless /tmp/gproj modem -process modem_combined.elf -noanalysis \
#        -scriptPath /tmp -postScript hunt.py
# @category Analysis
#

from ghidra.program.model.address import Address
from ghidra.program.model.symbol import RefType

OUT = "/tmp/hunt_results.txt"
out = open(OUT, "w")

def addr(va):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(va)

def dump_refs(target_va, label, ctx_bytes=32, max_hits=60):
    t = addr(target_va)
    refs = getReferencesTo(t)
    n = 0
    out.write(f"==== refs to {label} ({hex(target_va)}) ====\n")
    for r in refs:
        if n >= max_hits:
            out.write("  ... (more)\n"); break
        frm = r.getFromAddress()
        out.write(f"  ref from {frm} type={r.getReferenceType()}\n")
        # dump surrounding instruction listing
        try:
            ins = getInstructionAt(frm)
            if ins is None:
                ins = getInstructionBefore(frm)
            if ins is not None:
                fi = ins
                for _ in range(6):
                    out.write(f"      {fi.getAddress()}: {fi}\n")
                    fi = fi.getNextInstruction()
                    if fi is None: break
        except Exception as e:
            out.write(f"      (listing err {e})\n")
        n += 1
    out.write(f"  total listed: {n}\n\n")

# 1. UIM IDL string pool refs (msg-name vault in b20)
for va, lab in [
    (0xc5779da2, "IDL pool: (qe)qmi_uim..reset"),
    (0xc5779dcb, "IDL pool: (pe)qmi_uim..read_record"),
    (0xc577a2e6, "IDL pool: change_provisioning"),
    (0xc577a30b, "IDL pool: send_apdu"),
    (0xc577a334, "IDL pool: sap_connect/open_logical_channel"),
    (0xc577a370, "IDL pool: slots_status"),
    (0xc577a3c0, "IDL pool: slot_mapping/eid"),
    (0xc577a3fc, "IDL pool: profile/nickname"),
]:
    dump_refs(va, lab)

# 2. ISD-R AID bytes + apdu_security strings
for va, lab in [
    (0xc2109292, "ISD-R AID bytes (b15)"),
    (0xc4ddf450, "ISD-R AID bytes (b18)"),
    (0xc231f2f9, "apdu_security_aid_list str (b15)"),
    (0xc33cb4ae, "apdu_security_aid_list str (b16)"),
    (0xc2023698, "qmi_uim_m2m_euicc.c str"),
    (0xc2109190, "euiccChallenge str"),
]:
    dump_refs(va, lab)

# 3. F3 log core callers — dump a few with their arg setups
dump_refs(0xc0027e38, "F3 log core", max_hits=5)

# 4. scan for the UIM service object: search data for {.., 0x000B, ..} near IDL pool ptrs
out.write("==== u16 0x000B scan near pool refs (skipped: use python) ====\n")

out.close()
print("hunt.py done -> /tmp/hunt_results.txt")
