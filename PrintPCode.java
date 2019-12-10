//Print PCode
//@author saruman9
//@category PCode
//@keybinding ctrl 1
//@menupath
//@toolbar

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOpAST;

import java.util.Iterator;

public class PrintPCode extends GhidraScript {

    @Override
    public void run() throws Exception {

        DecompInterface ifc = new DecompInterface();
        Function function = currentProgram.getFunctionManager()
                                          .getFunctionContaining(currentAddress);

        println(String.format("Decompiling %s at %s",
                              function.getName(),
                              function.getEntryPoint()));
        ifc.openProgram(currentProgram);
        DecompileResults decompileResults = ifc.decompileFunction(function, 30, monitor);
        println("Decompilation completed: " + decompileResults.decompileCompleted());
        Iterator<PcodeOpAST> pcodeOpASTIterator = decompileResults.getHighFunction().getPcodeOps();
        StringBuilder pcodeHighString = new StringBuilder();
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST pcodeOpAST = pcodeOpASTIterator.next();
            pcodeHighString.append(String.format("%s\n", pcodeOpAST));
        }
        println(pcodeHighString.toString());
    }
}
