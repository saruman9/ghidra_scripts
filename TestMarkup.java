//Test markup
//@author saruman9
//@category Examples
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.util.template.TemplateSimplifier;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitFormatOptions;
import ghidra.program.model.listing.Instruction;

public class TestMarkup extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Instruction instruction = currentProgram.getListing().getInstructionAt(currentAddress);

        TemplateSimplifier simplifier = new TemplateSimplifier();
        simplifier.setEnabled(false);
        var options = new CodeUnitFormatOptions(CodeUnitFormatOptions.ShowBlockName.ALWAYS,
                CodeUnitFormatOptions.ShowNamespace.ALWAYS,
                "",
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                simplifier);
        CodeUnitFormat codeUnitFormat = new CodeUnitFormat(options);
        for (int i = 0; i < instruction.getNumOperands(); i++) {
            printf("op #%d: \"%s\"\n", i, codeUnitFormat.getOperandRepresentationString(instruction, i));
        }
    }
}
