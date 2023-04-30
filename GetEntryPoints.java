/*
 * Copyright (c) 2020 Abc Xyz — All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Parses PE header and print an entry point address (address of a valid function) from optional header.
//@author saruman9
//@category Windows
//@keybinding ctrl 1
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pe.NTHeader;
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

        ByteProvider byteProvider = new MemoryByteProvider(currentProgram.getMemory(), currentProgram.getImageBase());
        PortableExecutable portableExecutable = null;
        try {
            portableExecutable = new PortableExecutable(byteProvider, PortableExecutable.SectionLayout.MEMORY);
        } catch (IOException e) {
            printerr(e.toString());
            byteProvider.close();
            return;
        }

        NTHeader ntHeader = portableExecutable.getNTHeader();
        if (ntHeader == null) {
            printerr("NTHeader not found");
            byteProvider.close();
            return;
        }
        OptionalHeader optionalHeader = ntHeader.getOptionalHeader();
        if (optionalHeader == null) {
            printerr("OptionalHeader not found");
            byteProvider.close();
            return;
        }
        long longAddressEntry =
                optionalHeader.getAddressOfEntryPoint() + currentProgram.getImageBase().getOffset();
        printf("0x%08x\n", longAddressEntry);

        FunctionManager functionManager = currentProgram.getFunctionManager();
        AddressFactory addressFactory = currentProgram.getAddressFactory();
        Address addressEntry =
                addressFactory.getAddress(addressFactory.getDefaultAddressSpace().getSpaceID(),
                        longAddressEntry);

        Function function = functionManager.getFunctionContaining(addressEntry);
        printf("%s\n", function);
    }
}
