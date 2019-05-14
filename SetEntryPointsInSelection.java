//Set functions in selection as entry points.
//@author saruman9
//@category Selection
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.Msg;

public class SetEntryPointsInSelection extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            Msg.showError(this,
                    null,
                    "Error",
                    "This script should be run from a tool with open program.");
            return;
        }

        if (currentSelection == null) {
            Msg.showError(this,
                    null,
                    "Error",
                    "You should select needed functions.");
            return;
        }

        FunctionManager functionManager = currentProgram.getFunctionManager();
        AddressRangeIterator addressIterator = currentSelection.getAddressRanges();
        while (addressIterator.hasNext()) {
            AddressRange addressRange = addressIterator.next();
            Address entryPoint = addressRange.getMinAddress();
            if (functionManager.getFunctionAt(entryPoint) != null) {
                addEntryPoint(entryPoint);
            }
        }
    }
}
