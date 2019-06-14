//Find direct references.
//@author saruman9
//@category References
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramMemoryUtil;

import java.util.Set;

public class FindDirectReferences extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Set<Address> directReferences = ProgramMemoryUtil.findDirectReferences(currentProgram, 2, currentAddress, monitor);
        printf("%s\n", directReferences);

    }
}
