//Find all functions with parameters, which will be dereferenced.
//@author saruman9
//@category Functions
//@keybinding ctrl 1
//@menupath
//@toolbar

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitor;

import java.util.Iterator;

public class FindNeededFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            Msg.showError(this,
                    null,
                    "Error",
                    "This script should be run from a tool with open program.");
            return;
        }

        FunctionManager functionManager = currentProgram.getFunctionManager();
        FunctionIterator functionIterator = functionManager.getFunctions(true);
        DecompileOptions options = new DecompileOptions();
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(options);
        ifc.setSimplificationStyle("decompile");

        if (!ifc.openProgram(currentProgram)) {
            throw new DecompileException("Decompiler", "Unable to initialize: " + ifc.getLastMessage());
        }

        Function currentFunction = functionManager.getFunctionContaining(currentAddress);
//        processFunction(ifc, currentFunction);

        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            if (function.getParameterCount() > 0) {
                processFunction(ifc, function, monitor);
                if (monitor.isCancelled()) {
                    return;
                }
            }
        }

    }

    private void processFunction(DecompInterface ifc, Function function, TaskMonitor monitor) {
//        printf("processing %s : %s\n", function.getName(), function.getEntryPoint());

        HighFunction high = getHighFunction(ifc, function);

        Iterator<PcodeOpAST> opASTIterator = high.getPcodeOps();
        PcodeOpAST storeOp = null;
        while (opASTIterator.hasNext()) {
            PcodeOpAST op = opASTIterator.next();
            if (op != null) {
//                printf("%s\n", op);
                if (op.getOpcode() == PcodeOp.STORE) {
                    Varnode storeVarnode = op.getInput(1);
                    Varnode varnode = findRootOfVarnode(storeVarnode, monitor);
                    if (monitor.isCancelled()) {
                        return;
                    }
                    if (varnode != null) {
                        printf("Function: %s ( %s ), %s\n", function.getName(), function.getEntryPoint(), varnode);
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
            printf("\nWARNING: %s returned null HighFunction\n", func);
        }
        return high;
    }

    private Varnode findRootOfVarnode(Varnode varnode, TaskMonitor monitor) {
        if (monitor.isCancelled()) {
            return null;
        }
        HighVariable highVariable = varnode.getHigh();
        if (highVariable instanceof HighParam) {
//            printf("\nIt's param! %s\n", highVariable);
            return varnode;
        }
        PcodeOp pcodeOp = varnode.getDef();
        if (pcodeOp == null) {
//            printf("WARNING! Pcode NULL. %s\n", varnode);
//            return varnode;
            return null;
        }
        int opcode = pcodeOp.getOpcode();
        switch (opcode) {
            case PcodeOp.STORE:
            case PcodeOp.LOAD: {
                return findRootOfVarnode(pcodeOp.getInput(1), monitor);
            }
            case PcodeOp.INT_MULT:
            case PcodeOp.INDIRECT:
            case PcodeOp.MULTIEQUAL:
            case PcodeOp.INT_NEGATE:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_SEXT:
            case PcodeOp.INT_RIGHT:
            case PcodeOp.INT_LEFT:
            case PcodeOp.INT_SUB:
            case PcodeOp.INT_XOR:
            case PcodeOp.INT_AND:
            case PcodeOp.INT_OR:
            case PcodeOp.CAST:
            case PcodeOp.COPY:
            case PcodeOp.PTRADD:
            case PcodeOp.PTRSUB:
            case PcodeOp.INT_ADD: {
                return findRootOfVarnode(pcodeOp.getInput(0), monitor);
            }
            case PcodeOp.CALL: {
//                printf("WARNING! Pcode CALL\n");
                return null;
            }

            default:
                throw new NotYetImplementedException("Support for PcodeOp " + pcodeOp.toString() + " not implemented");
        }
    }
}
