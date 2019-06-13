//Remove all references to data.
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

public class RemoveAllReferencesToAddress extends GhidraScript {

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
                removeReferencesToAddress(address);
            }
        } else {
            removeReferencesToAddress(currentAddress);
        }
    }

    private void removeReferencesToAddress(Address addressTo) {
        Reference[] references = getReferencesTo(addressTo);
        for (Reference reference : references) {
            removeReference(reference);
        }
    }
}
