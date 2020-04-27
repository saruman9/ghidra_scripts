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
//Basic block model example.
//@author saruman9
//@category Examples
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;

public class BasicBlockModelExample extends GhidraScript {

    @Override
    protected void run() throws Exception {
        BasicBlockModel basicBlockModel = new BasicBlockModel(currentProgram);
        FunctionManager functionManager = currentProgram.getFunctionManager();
        for (Function currentFunction : functionManager.getFunctions(true)) {
            printf("Function: %s ( %s )\n", currentFunction.getName(),
                    currentFunction.getEntryPoint());
            CodeBlockIterator codeBlockIterator =
                    basicBlockModel.getCodeBlocksContaining(currentFunction.getBody(), monitor);
            while (codeBlockIterator.hasNext()) {
                CodeBlock codeBlock = codeBlockIterator.next();
                printf("\n\tCode Block: %s ( %s )\n", codeBlock.getName(),
                        codeBlock.getFirstStartAddress());

                CodeBlockReferenceIterator codeBlockReferenceSourcesIterator =
                        codeBlock.getSources(monitor);
                printf("\t\tSources:\n");
                while (codeBlockReferenceSourcesIterator.hasNext()) {
                    CodeBlockReference codeBlockReference =
                            codeBlockReferenceSourcesIterator.next();
                    CodeBlock codeBlockSource = codeBlockReference.getSourceBlock();
                    printf("\t\t%s ( %s )\n", codeBlockSource.getName(),
                            codeBlockSource.getFirstStartAddress());
                }
                CodeBlockReferenceIterator codeBlockReferenceDestsIterator =
                        codeBlock.getDestinations(monitor);
                printf("\n\t\tDestinations:\n");
                while (codeBlockReferenceDestsIterator.hasNext()) {
                    CodeBlockReference codeBlockReference = codeBlockReferenceDestsIterator.next();
                    CodeBlock codeBlockDest = codeBlockReference.getDestinationBlock();
                    printf("\t\t%s ( %s )\n", codeBlockDest.getName(),
                            codeBlockDest.getFirstStartAddress());
                }

                Listing listing = currentProgram.getListing();
                CodeUnitIterator codeUnitIterator = listing.getCodeUnits(codeBlock, true);
                while (codeUnitIterator.hasNext()) {
                    printf("\t%s\n", codeUnitIterator.next());
                }
            }
        }
    }
}
