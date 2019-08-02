//Basic block model example.
//@author saruman9
//@category Examples
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;

public class BasicBlockModelExample extends GhidraScript {

    @Override
    protected void run() throws Exception {
        BasicBlockModel basicBlockModel = new BasicBlockModel(currentProgram);
        FunctionManager functionManager = currentProgram.getFunctionManager();
        for (Function currentFunction : functionManager.getFunctions(true)) {
            printf("Function: %s ( %s )\n", currentFunction.getName(), currentFunction.getEntryPoint());
            CodeBlockIterator codeBlockIterator = basicBlockModel.getCodeBlocksContaining(currentFunction.getBody(), monitor);
            while (codeBlockIterator.hasNext()) {
                CodeBlock codeBlock = codeBlockIterator.next();
                printf("\n\tCode Block: %s ( %s )\n", codeBlock.getName(), codeBlock.getFirstStartAddress());

                CodeBlockReferenceIterator codeBlockReferenceSourcesIterator = codeBlock.getSources(monitor);
                printf("\t\tSources:\n");
                while (codeBlockReferenceSourcesIterator.hasNext()) {
                    CodeBlockReference codeBlockReference = codeBlockReferenceSourcesIterator.next();
                    CodeBlock codeBlockSource = codeBlockReference.getSourceBlock();
                    printf("\t\t%s ( %s )\n", codeBlockSource.getName(), codeBlockSource.getFirstStartAddress());
                }
                CodeBlockReferenceIterator codeBlockReferenceDestsIterator = codeBlock.getDestinations(monitor);
                printf("\n\t\tDestinations:\n");
                while (codeBlockReferenceDestsIterator.hasNext()) {
                    CodeBlockReference codeBlockReference = codeBlockReferenceDestsIterator.next();
                    CodeBlock codeBlockDest = codeBlockReference.getDestinationBlock();
                    printf("\t\t%s ( %s )\n", codeBlockDest.getName(), codeBlockDest.getFirstStartAddress());
                }

                Listing listing = currentProgram.getListing();
                CodeUnitIterator codeUnitIterator = listing.getCodeUnits(codeBlock, true);
                while (codeUnitIterator.hasNext()) {
                    printf("\t%s\n", codeUnitIterator.next());
                }
            }
        }
    }
}
