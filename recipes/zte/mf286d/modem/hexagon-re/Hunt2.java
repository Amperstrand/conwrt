import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class Hunt2 extends GhidraScript {
    java.io.FileWriter out;

    void w(String s) throws Exception { out.write(s); out.flush(); }

    Function funcOf(Address a) {
        Function f = getFunctionContaining(a);
        return f;
    }

    void refsTo(long target, String label, int max) throws Exception {
        Address t = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target);
        w("\n==== refs to " + label + " (0x" + Long.toHexString(target) + ") ====\n");
        int n = 0;
        for (Reference r : getReferencesTo(t)) {
            if (n++ >= max) { w("  ...more\n"); break; }
            Address frm = r.getFromAddress();
            Function f = funcOf(frm);
            w("  from " + frm + " in " + (f != null ? f.getName() + " @" + f.getEntryPoint() : "?") +
              " type=" + r.getReferenceType() + "\n");
            // list a few instructions around
            Instruction ins = getInstructionAt(frm);
            if (ins == null) ins = getInstructionBefore(frm);
            for (int k = 0; k < 6 && ins != null; k++) {
                w("     " + ins.getAddress() + ": " + ins + "\n");
                Address na = ins.getAddress().add(ins.getLength());
                ins = getInstructionAt(na);
            }
        }
        w("  total " + n + "\n");
    }

    @Override
    public void run() throws Exception {
        out = new java.io.FileWriter("/tmp/hunt2_results.txt");
        // 1. who references the UIM service object + its msg tables
        refsTo(0xc32c0650L, "UIM IDL service object", 20);
        refsTo(0xc2316358L, "REQ msgid_to_msg table", 20);
        refsTo(0xc2316508L, "RESP msgid_to_msg table", 20);
        refsTo(0xc32c0654L, "svc obj field idl_version", 10);
        // 2. string anchors for m2m_euicc module
        refsTo(0xc2023698L, "qmi_uim_m2m_euicc.c string", 20);
        // 3. type table
        refsTo(0xc2316774L, "UIM type table object", 20);
        out.close();
        println("Hunt2 done -> /tmp/hunt2_results.txt");
    }
}
