import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class Hunt extends GhidraScript {
    String fmt(Reference r) { return r == null ? "null" : r.toString(); }

    void dumpRefs(long target, String label, int maxHits) throws Exception {
        Address t = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target);
        StringBuilder sb = new StringBuilder();
        sb.append("==== refs to ").append(label).append(" (0x").append(Long.toHexString(target)).append(") ====\n");
        int n = 0;
        for (Reference r : getReferencesTo(t)) {
            if (n >= maxHits) { sb.append("  ...more\n"); break; }
            Address frm = r.getFromAddress();
            sb.append("  ref from ").append(frm).append(" type=").append(r.getReferenceType()).append("\n");
            Instruction ins = getInstructionAt(frm);
            if (ins == null) ins = getInstructionBefore(frm);
            if (ins != null) {
                ghidra.program.model.address.Address a = ins.getAddress();
                for (int k = 0; k < 6; k++) {
                    Instruction fi = currentProgram.getListing().getInstructionAt(a);
                    if (fi == null) break;
                    sb.append("      ").append(fi.getAddress()).append(": ").append(fi).append("\n");
                    ghidra.program.model.address.Address na =
                        currentProgram.getListing().getInstructionAfter(a).getAddress();
                    if (na.compareTo(a) <= 0) break;
                    a = na;
                }
            }
            n++;
        }
        sb.append("  total: ").append(n).append("\n\n");
        write(sb.toString());
    }

    void write(String s) throws Exception {
        java.io.FileWriter fw = new java.io.FileWriter("/tmp/hunt_results.txt", true);
        fw.write(s); fw.close();
    }

    @Override
    public void run() throws Exception {
        new java.io.File("/tmp/hunt_results.txt").delete();

        dumpRefs(0xc5779da2L, "IDLpool:qmi_uim..reset", 40);
        dumpRefs(0xc5779dcbL, "IDLpool:read_record", 40);
        dumpRefs(0xc577a2e6L, "IDLpool:change_provisioning", 40);
        dumpRefs(0xc577a30bL, "IDLpool:send_apdu", 40);
        dumpRefs(0xc577a334L, "IDLpool:sap_connect/open_logical_channel", 40);
        dumpRefs(0xc577a370L, "IDLpool:slots_status", 40);
        dumpRefs(0xc577a3c0L, "IDLpool:slot_mapping/eid", 40);
        dumpRefs(0xc577a3fcL, "IDLpool:profile/nickname", 40);

        dumpRefs(0xc2109292L, "ISD-R AID bytes (b15)", 40);
        dumpRefs(0xc4ddf450L, "ISD-R AID bytes (b18)", 40);
        dumpRefs(0xc231f2f9L, "apdu_security_aid_list str (b15)", 40);
        dumpRefs(0xc33cb4aeL, "apdu_security_aid_list str (b16)", 40);
        dumpRefs(0xc2023698L, "qmi_uim_m2m_euicc.c str", 40);
        dumpRefs(0xc2109190L, "euiccChallenge str", 20);

        dumpRefs(0xc0027e38L, "F3 log core", 5);

        println("Hunt done -> /tmp/hunt_results.txt");
    }
}
