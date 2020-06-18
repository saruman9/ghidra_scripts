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
//Commit parameters and return type to database.
//@author saruman9
//@category Functions
//@keybinding ctrl 1
//@menupath
//@toolbar

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;

public class CommitParamsReturn extends GhidraScript {

    @Override
    public void run() throws Exception {

        DecompInterface ifc = new DecompInterface();
        try {
            Function function = currentProgram.getFunctionManager()
                                              .getFunctionContaining(currentAddress);
            println(String.format("Decompiling %s at %s", function.getName(),
                                  function.getEntryPoint()));
            ifc.openProgram(currentProgram);
            DecompileResults decompileResults = ifc.decompileFunction(function, 30, monitor);
            println("Decompilation completed: " + decompileResults.decompileCompleted());

            // Print signature from decompiler
            HighFunction highFunction = decompileResults.getHighFunction();
            FunctionPrototype functionPrototype = highFunction.getFunctionPrototype();
            println(functionPrototype.getReturnType().toString());
            for (int i = 0; i < functionPrototype.getNumParams(); i++) {
                HighSymbol parameter = functionPrototype.getParam(i);
                println(parameter.getDataType().toString() + " " + parameter.getName());
            }

            // Commit
            HighFunctionDBUtil.commitReturnToDatabase(highFunction, SourceType.ANALYSIS);
            HighFunctionDBUtil.commitParamsToDatabase(highFunction, true, SourceType.ANALYSIS);
        } finally {
            ifc.dispose();
        }
    }
}
