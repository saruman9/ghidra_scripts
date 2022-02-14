//Rename all functions in the selection.
//@author saruman9
//@category Selection
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

public class RenameFunctionsInSelection extends GhidraScript {

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

        String namespaceString = askString("Function name", "Namespace:");
        String name = askString("Function name", "Name:");
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        Namespace globalNamespace = currentProgram.getGlobalNamespace();
        Namespace namespace = symbolTable.getNamespace(namespaceString, globalNamespace);
        if (namespace == null) {
            namespace = symbolTable.createNameSpace(globalNamespace, namespaceString, SourceType.ANALYSIS);
        }

        FunctionManager functionManager = currentProgram.getFunctionManager();
        AddressRangeIterator addressIterator = currentSelection.getAddressRanges();
        while (addressIterator.hasNext()) {
            AddressRange addressRange = addressIterator.next();
            Address entryPoint = addressRange.getMinAddress();
            Function function = functionManager.getFunctionAt(entryPoint);
            if (function != null) {
                function.getSymbol().setNameAndNamespace(name, namespace, SourceType.ANALYSIS);
            }
        }
    }
}
