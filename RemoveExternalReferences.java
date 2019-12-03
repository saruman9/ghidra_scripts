//Remove old external references
//@author saruman9
//@category References.External
//@keybinding ctrl 1
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

public class RemoveExternalReferences extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            Msg.showError(this,
                    null,
                    "Error",
                    "This script should be run from a tool with open program.");
            return;
        }

        ExternalManager externalManager = currentProgram.getExternalManager();
        ReferenceManager referenceManager = currentProgram.getReferenceManager();

        for (String libraryNames : externalManager.getExternalLibraryNames()) {
            ExternalLocationIterator externalLocationIterator =
                    externalManager.getExternalLocations(libraryNames);
            while (externalLocationIterator.hasNext()) {
                ExternalLocation externalLocation = externalLocationIterator.next();
                for (Reference referenceExternal : referenceManager
                        .getReferencesTo(externalLocation.getExternalSpaceAddress())) {
                    referenceManager.addMemoryReference(referenceExternal.getFromAddress(),
                            externalLocation.getAddress(),
                            referenceExternal.getReferenceType(),
                            SourceType.ANALYSIS,
                            referenceExternal.getOperandIndex());
                }
            }
        }
    }
}
