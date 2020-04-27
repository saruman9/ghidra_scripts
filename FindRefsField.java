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