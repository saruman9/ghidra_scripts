//Find all symbols with multiple labels. Maybe useful for Version Tracking session.
//@author saruman9
//@category Symbol
//@keybinding ctrl 1
//@menupath
//@toolbar

import generic.continues.RethrowContinuesFactory;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.Msg;

import java.io.IOException;

public class GetEntryPoints extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            Msg.showError(this,
                    null,
                    "Error",
                    "This script should be run from a tool with open program.");
            return;
        }
//        SymbolTable symbolTable = currentProgram.getSymbolTable();
//        FunctionManager functionManager = currentProgram.getFunctionManager();
//        AddressIterator addressIterator = symbolTable.getExternalEntryPointIterator();
//        while (addressIterator.hasNext()) {
//            Address address = addressIterator.next();
//            Function function = functionManager.getFunctionContaining(address);
//            printf("%s\n", function);
//        }

        ByteProvider byteProvider = new MemoryByteProvider(currentProgram.getMemory(),
                currentProgram.getImageBase());
        PortableExecutable portableExecutable = null;
        try {
            portableExecutable = PortableExecutable.createPortableExecutable(RethrowContinuesFactory.INSTANCE,
                    byteProvider, PortableExecutable.SectionLayout.MEMORY);
        } catch (IOException e) {
            Msg.error(this, e.toString());
            byteProvider.close();
            return;
        }

        OptionalHeader optionalHeader = portableExecutable.getNTHeader().getOptionalHeader();
        long longAddressEntry =
                optionalHeader.getAddressOfEntryPoint() + currentProgram.getImageBase().getOffset();
        printf("0x%08x\n", longAddressEntry);

        FunctionManager functionManager = currentProgram.getFunctionManager();
        AddressFactory addressFactory = currentProgram.getAddressFactory();
        Address addressEntry =
                addressFactory.getAddress(addressFactory.getDefaultAddressSpace().getBaseSpaceID(),
                        longAddressEntry);

        Function function = functionManager.getFunctionContaining(addressEntry);
        printf("%s\n", function);
    }
}
