//Remove all references from address.
//@author saruman9
//@category References
//@keybinding ctrl 1
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;

public class RemoveAllReferencesFromAddress extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            Msg.showError(this,
                    null,
                    "Error",
                    "This script should be run from a tool with open program.");
            return;
        }
        if (currentSelection != null) {
            AddressIterator addresses = currentSelection.getAddresses(true);
            while (addresses.hasNext()) {
                Address address = addresses.next();
                removeReferencesFromAddress(address);
            }
        } else {
            removeReferencesFromAddress(currentAddress);
        }
    }

    private void removeReferencesFromAddress(Address addressFrom) {
        Reference[] references = getReferencesFrom(addressFrom);
        for (Reference reference : references) {
            removeReference(reference);
        }
    }
}
