//Find references to the field of a structure.
//@author saruman9
//@category References
//@keybinding ctrl 1
//@menupath
//@toolbar

import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReference;
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.util.datastruct.ListAccumulator;

public class FindRefsField extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (!(currentLocation instanceof DecompilerLocation)) {
            printerr("You should set the cursor in Decompiler window.");
            return;
        }
        ClangToken tokenAtCursor = ((DecompilerLocation) currentLocation).getToken();
        if (!(tokenAtCursor instanceof ClangFieldToken)) {
            printerr("You should set the cursor on the field of a structure.");
            return;
        }

        DataType dataType = ((ClangFieldToken) tokenAtCursor).getDataType();
        DataType baseDataType = ReferenceUtils.getBaseDataType(dataType);
        String fieldName = tokenAtCursor.getText();

        ListAccumulator<LocationReference> accumulator = new ListAccumulator<>();

        ReferenceUtils.findDataTypeReferences(accumulator,
                                              baseDataType,
                                              fieldName,
                                              currentProgram,
                                              monitor
        );

        for (LocationReference locationReference : accumulator) {
            println(locationReference.toString());
        }
    }
}