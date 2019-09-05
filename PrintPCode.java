/*
 * analyzeHeadless . temp.gpr -import $BINARY_NAME -preScript PrintPCode.java $FUNCTION_ADDRESS $TYPE -deleteProject -noanalysis
 */

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.Msg;

import java.util.Iterator;

public class PrintPCode extends HeadlessScript {

    @Override
    public void run() throws Exception {

        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);

        String[] args = getScriptArgs();
        if (args.length < 2) {
            Msg.error(this, "USAGE: PrintPCode.java ADDRESS [asm,pcode,pcodehigh,c]");
            return;
        }
        String typeOfPrint = args[1];

        DecompInterface ifc = new DecompInterface();

        Address addressFunction = getAddressFactory().getAddress(args[0]);
        if (addressFunction == null) {
            Msg.error(this, String.format("Address not found at %s\n", args[0]));
            return;
        }

        disassemble(addressFunction);
        Function f = createFunction(addressFunction, "Test");
        if (f == null) {
            Msg.error(this, String.format("Function not found at %s", args[0]));
            return;
        }

        Listing listing = currentProgram.getListing();
        InstructionIterator instructionIterator = listing.getInstructions(f.getBody(), true);
        switch (typeOfPrint) {
            case "asm":
                StringBuilder instructionsString = new StringBuilder();
                while (instructionIterator.hasNext()) {
                    Instruction instruction = instructionIterator.next();
                    instructionsString.append(String.format("%s\t%s\n", instruction.getAddress(), instruction));
                }
                println(instructionsString.toString());
                return;
            case "pcode":
                StringBuilder pcodeString = new StringBuilder();
                while (instructionIterator.hasNext()) {
                    Instruction instruction = instructionIterator.next();
                    pcodeString.append(String.format("%s\t%s\n", instruction.getAddress(), instruction));
                    for (PcodeOp pcodeOp : instruction.getPcode()) {
                        pcodeString.append(String.format("\t%s\n", pcodeOp));
                    }
                }
                println(pcodeString.toString());
                return;
        }

        println(String.format("Decompiling %s at %s", f.getName(), addressFunction));
        ifc.openProgram(f.getProgram());
        DecompileResults decompileResults = ifc.decompileFunction(f, 30, null);
        println("Decompilation completed: " + decompileResults.decompileCompleted());
        switch (typeOfPrint) {
            case "pcodehigh":
                Iterator<PcodeOpAST> pcodeOpASTIterator = decompileResults.getHighFunction().getPcodeOps();
                StringBuilder pcodeHighString = new StringBuilder();
                while (pcodeOpASTIterator.hasNext()) {
                    PcodeOpAST pcodeOpAST = pcodeOpASTIterator.next();
                    pcodeHighString.append(String.format("%s\n", pcodeOpAST));
                }
                println(pcodeHighString.toString());
                return;
            case "c":
                DecompiledFunction df = decompileResults.getDecompiledFunction();
                println(df.getC());
        }
    }
}
