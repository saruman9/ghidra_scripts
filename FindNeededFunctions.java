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
//Find all functions with parameters, which will be dereferenced.
//@author saruman9
//@category Functions
//@keybinding ctrl 1
//@menupath
//@toolbar

import generic.stl.Pair;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitor;

import java.util.Arrays;
import java.util.Iterator;

public class FindNeededFunctions extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            Msg.showError(this,
                          null,
                          "Error",
                          "This script should be run from a tool with open program."
            );
            return;
        }

        FunctionManager functionManager = currentProgram.getFunctionManager();
        FunctionIterator functionIterator = functionManager.getFunctions(true);
        DecompileOptions options = new DecompileOptions();
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(options);
        ifc.setSimplificationStyle("decompile");

        if (!ifc.openProgram(currentProgram)) {
            throw new DecompileException("Decompiler",
                                         "Unable to initialize: " + ifc.getLastMessage()
            );
        }

        Function currentFunction = functionManager.getFunctionContaining(currentAddress);
//        printFunction(ifc, currentFunction, monitor);
//        processFunction(ifc, currentFunction, monitor);
//        return;

        printf("NmFun, AdrFunHex, AdrFunDec, SzFun, StOffSrc, StOffDst\n");

        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            if (function.getParameterCount() > 0 && isFoundNeededBytes(function)) {
                processFunction(ifc, function, monitor);
                if (monitor.isCancelled()) {
                    return;
                }
            }
        }
    }


    private boolean isFoundNeededBytes(Function function) {
        Address addressBytes = function.getEntryPoint().subtract(4);
        byte[] standardBytes = new byte[]{(byte) 0xF3, 0x0F, 0x1E, (byte) 0xFB};
        try {
            byte[] bytes = getBytes(addressBytes, 4);
            return Arrays.equals(bytes, standardBytes);
        } catch (MemoryAccessException e) {
            return false;
        }
    }

    private void printFunction(DecompInterface ifc, Function function, TaskMonitor monitor) {
        HighFunction highFunction = getHighFunction(ifc, function);
        if (highFunction == null) {
            return;
        }

        Iterator<PcodeOpAST> opASTIterator = highFunction.getPcodeOps();
        while (opASTIterator.hasNext()) {
            PcodeOpAST op = opASTIterator.next();
            if (op != null) {
                printf("%s\n", op);
            }
        }
    }

    private void processFunction(DecompInterface ifc, Function function, TaskMonitor monitor) {
//        printf("processing %s : %s\n", function.getName(), function.getEntryPoint());

        HighFunction high = getHighFunction(ifc, function);
        if (high == null) {
            return;
        }

        Iterator<PcodeOpAST> opASTIterator = high.getPcodeOps();
        PcodeOpAST storeOp = null;
        while (opASTIterator.hasNext()) {
            PcodeOpAST op = opASTIterator.next();
            if (op != null) {
//                printf("%s\n", op);
                if (op.getOpcode() == PcodeOp.STORE) {
                    Varnode storeDstVarnode = op.getInput(1);
                    Varnode storeSrcVarnode = op.getInput(2);
                    try {
                        Pair<Varnode, Integer> varnodeDst =
                                findRootOfVarnode(storeDstVarnode, 0, monitor);
                        Pair<Varnode, Integer> varnodeSrc =
                                findRootOfSrcVarnode(storeSrcVarnode, false, 0, monitor);
                        if (monitor.isCancelled()) {
                            return;
                        }
                        if (varnodeDst != null && varnodeSrc != null) {
//                            HighVariable highVariable = varnode.getHigh();
                            int stackOffsetDst =
                                    varnodeDst.first.getHigh().getStorage().getStackOffset();
                            int stackOffsetSrc =
                                    varnodeSrc.first.getHigh().getStorage().getStackOffset();
//                            if ((stackOffsetDst == 0x4 || stackOffsetDst == 0x10) && (stackOffsetSrc == 0x4 || stackOffsetSrc == 0x10)) {
                            printf("%s, 0x%x, %d, %d, 0x%x, 0x%x\n",
                                   function.getName(),
                                   function.getEntryPoint().getOffset(),
                                   function.getEntryPoint().getOffset(),
                                   function.getBody().getNumAddresses(),
                                   stackOffsetSrc,
                                   stackOffsetDst
                            );
//                            }
//                            printf("%s, %s\n", highVariable, highVariable.getStorage().getStackOffset());
//                            return;
                        }
                    } catch (StackOverflowError e) {
//                        printf("WARNING! StackOverflowError\n");
                        return;
                    }
                }
            }
        }
    }

    private HighFunction getHighFunction(DecompInterface ifc, Function func) {
        DecompileResults res = ifc.decompileFunction(func, 300, null);
        HighFunction high = res.getHighFunction();
        if (high == null) {
            printf("\nWARNING: %s ( %s ) returned null HighFunction\n", func.getName(),
                   func.getEntryPoint()
            );
        }
        return high;
    }

    private Pair<Varnode, Integer> findRootOfVarnode(Varnode varnode, int jumps,
                                                     TaskMonitor monitor) {
        if (monitor.isCancelled()) {
            return null;
        }
        HighVariable highVariable = varnode.getHigh();
        if (highVariable instanceof HighParam) {
//            printf("\nIt's param! %s\n", highVariable);
            return new Pair<>(varnode, jumps);
        }
        PcodeOp pcodeOp = varnode.getDef();
//        printf("DEF (%s): %s\n", varnode, pcodeOp);
        if (pcodeOp == null) {
//            printf("WARNING! Pcode NULL. %s\n", varnode);
//            return varnode;
            return null;
        }
        int opcode = pcodeOp.getOpcode();
        switch (opcode) {
            case PcodeOp.STORE:
            case PcodeOp.LOAD: {
                return findRootOfVarnode(pcodeOp.getInput(1), jumps + 1, monitor);
            }
            case PcodeOp.BOOL_AND:
            case PcodeOp.BOOL_OR:
            case PcodeOp.BOOL_XOR:
            case PcodeOp.CAST:
            case PcodeOp.COPY:
            case PcodeOp.INDIRECT:
            case PcodeOp.INT_2COMP:
            case PcodeOp.INT_ADD:
            case PcodeOp.INT_AND:
            case PcodeOp.INT_DIV:
            case PcodeOp.INT_EQUAL:
            case PcodeOp.INT_LEFT:
            case PcodeOp.INT_LESS:
            case PcodeOp.INT_MULT:
            case PcodeOp.INT_NEGATE:
            case PcodeOp.INT_NOTEQUAL:
            case PcodeOp.INT_OR:
            case PcodeOp.INT_REM:
            case PcodeOp.INT_RIGHT:
            case PcodeOp.INT_SEXT:
            case PcodeOp.INT_SUB:
            case PcodeOp.INT_XOR:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.MULTIEQUAL:
            case PcodeOp.PIECE:
            case PcodeOp.PTRADD:
            case PcodeOp.PTRSUB:
            case PcodeOp.SUBPIECE: {
                return findRootOfVarnode(pcodeOp.getInput(0), jumps + 1, monitor);
            }
            case PcodeOp.CALLIND:
            case PcodeOp.CALL: {
//                printf("WARNING! Pcode CALL\n");
                return null;
            }

            default:
                throw new NotYetImplementedException(
                        "Support for PcodeOp " + pcodeOp.toString() + " not implemented");
        }
    }

    private Pair<Varnode, Integer> findRootOfSrcVarnode(Varnode varnode, boolean isDereferenced,
                                                        int jumps, TaskMonitor monitor) {
        if (monitor.isCancelled()) {
            return null;
        }
        HighVariable highVariable = varnode.getHigh();
        if (highVariable instanceof HighParam) {
//            printf("\nIt's param! %s\n", highVariable);
            if (isDereferenced) {
                return new Pair<>(varnode, jumps);
            } else {
                return null;
            }
        }
        PcodeOp pcodeOp = varnode.getDef();
//        printf("DEF (%s): %s\n", varnode, pcodeOp);
        if (pcodeOp == null) {
//            printf("WARNING! Pcode NULL. %s\n", varnode);
//            return varnode;
            return null;
        }
        int opcode = pcodeOp.getOpcode();
        switch (opcode) {
            case PcodeOp.STORE:
            case PcodeOp.LOAD: {
                return findRootOfSrcVarnode(pcodeOp.getInput(1), true, jumps + 1, monitor);
            }
            case PcodeOp.BOOL_AND:
            case PcodeOp.BOOL_OR:
            case PcodeOp.BOOL_XOR:
            case PcodeOp.CAST:
            case PcodeOp.COPY:
            case PcodeOp.INDIRECT:
            case PcodeOp.INT_2COMP:
            case PcodeOp.INT_ADD:
            case PcodeOp.INT_AND:
            case PcodeOp.INT_DIV:
            case PcodeOp.INT_EQUAL:
            case PcodeOp.INT_LEFT:
            case PcodeOp.INT_LESS:
            case PcodeOp.INT_MULT:
            case PcodeOp.INT_NEGATE:
            case PcodeOp.INT_NOTEQUAL:
            case PcodeOp.INT_OR:
            case PcodeOp.INT_REM:
            case PcodeOp.INT_RIGHT:
            case PcodeOp.INT_SEXT:
            case PcodeOp.INT_SUB:
            case PcodeOp.INT_XOR:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.MULTIEQUAL:
            case PcodeOp.PIECE:
            case PcodeOp.PTRADD:
            case PcodeOp.PTRSUB:
            case PcodeOp.SUBPIECE: {
                return findRootOfSrcVarnode(pcodeOp.getInput(0), isDereferenced, jumps + 1,
                                            monitor
                );
            }
            case PcodeOp.CALLIND:
            case PcodeOp.CALL: {
//                printf("WARNING! Pcode CALL\n");
                return null;
            }

            default:
                throw new NotYetImplementedException(
                        "Support for PcodeOp " + pcodeOp.toString() + " not implemented");
        }
    }
}
