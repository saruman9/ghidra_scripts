//Basic block model example.
//@author saruman9
//@category Examples
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Listing;

public class BasicBlockModelExample extends GhidraScript {

    @Override
    protected void run() throws Exception {
        BasicBlockModel basicBlockModel = new BasicBlockModel(currentProgram);
        CodeBlock[] codeBlock = basicBlockModel.getCodeBlocksContaining(currentAddress, monitor);
        Listing listing = currentProgram.getListing();
        CodeUnitIterator codeUnitIterator = listing.getCodeUnits(codeBlock[0], true);
        while (codeUnitIterator.hasNext()) {
            printf("%s\n", codeUnitIterator.next());
        }
    }
}
