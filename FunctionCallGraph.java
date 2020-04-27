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
//Create function call graph
//@author saruman9
//@category Functions
//@keybinding ctrl 1
//@menupath
//@toolbar

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.graph.AbstractDependencyGraph;
import ghidra.util.graph.DependencyGraph;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class FunctionCallGraph extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Function currentFunction = currentProgram.getFunctionManager()
                                                 .getFunctionContaining(currentAddress);
        AcyclicCallGraphWithParamsBuilder builder = new AcyclicCallGraphWithParamsBuilder(
                currentProgram,
                currentFunction,
                this,
                monitor
        );
        AbstractDependencyGraph<FunctionWithParams> graph = builder.getDependencyGraph();
        FunctionWithParams firstIndependentValue =
                (FunctionWithParams) graph.getAllIndependentValues()
                                          .toArray()[0];
        println(graph.getAllIndependentValues().toString());
        printDependencyGraph(graph, firstIndependentValue, 0);
    }

    private void printDependencyGraph(AbstractDependencyGraph<FunctionWithParams> graph,
                                      FunctionWithParams dependentValue,
                                      int depth) {
        for (FunctionWithParams currentFunctionWithParams : graph
                .getDependentValues(dependentValue)) {
            int i = depth;
            while (i > 0) {
                printf("    ");
                i--;
            }
            printf("%s\n", currentFunctionWithParams.toString());
            printDependencyGraph(graph, currentFunctionWithParams, depth + 1);
        }
    }
}

class AcyclicCallGraphWithParamsBuilder {
    private Program program;
    private Function functionRoot;
    // TODO Delete
    private GhidraScript ghidraScript;
    private int depthLimit = 1;
    private TaskMonitor monitor;

    AcyclicCallGraphWithParamsBuilder(Program program,
                                      Function functionRoot,
                                      GhidraScript ghidraScript,
                                      TaskMonitor monitor) {
        this.program = program;
        this.functionRoot = functionRoot;
        this.ghidraScript = ghidraScript;
        this.monitor = monitor;
    }

    AbstractDependencyGraph<FunctionWithParams> getDependencyGraph() {
        AbstractDependencyGraph<FunctionWithParams> graph = new DependencyGraph<>();
        try {
            fillGraph(graph, new FunctionWithParams(functionRoot), new LinkedList<>(), 0);
        } catch (CancelledException e) {
            return graph;
        }
        return graph;
    }

    private void fillGraph(AbstractDependencyGraph<FunctionWithParams> graph,
                           FunctionWithParams functionWithParams,
                           Deque<Function> visitedFunctions,
                           int depth) throws CancelledException {
        if (depth > depthLimit) {
            return;
        }
        if (visitedFunctions.contains(functionWithParams.getFunction())) {
            return;
        }
        visitedFunctions.push(functionWithParams.getFunction());
        FunctionManager functionManager = program.getFunctionManager();
        Symbol symbol = functionWithParams.getFunction().getSymbol();
        Reference[] references = symbol.getReferences(monitor);
        for (Reference reference : references) {
            monitor.checkCanceled();
            if (!reference.getReferenceType().isCall()) {
                continue;
            }
            Function functionReferenced =
                    functionManager.getFunctionContaining(reference.getFromAddress());
            if (functionReferenced == null) {
                ghidraScript.printerr(String.format("Function error: %s",
                                                    reference.getFromAddress()
                ));
                continue;
            }
            FunctionWithParams referenceFunctionWithParams = new FunctionWithParams(
                    functionReferenced,
                    findParametersDependence(functionWithParams.getFunction(), functionReferenced)
            );
            graph.addDependency(referenceFunctionWithParams, functionWithParams);
            fillGraph(graph, referenceFunctionWithParams, visitedFunctions, depth + 1);
        }
        visitedFunctions.pop();
    }

    private List<ParameterDependence> findParametersDependence(Function sourceFunction,
                                                               Function targetFunction) {
        DecompInterface decompInterface = new DecompInterface();
        List<ParameterDependence> parameterDependencies = new ArrayList<>();
        for (int i = 0; i < sourceFunction.getParameterCount(); i++) {
            parameterDependencies.add(new ParameterDependence());
        }
        try {
            decompInterface.openProgram(sourceFunction.getProgram());
            DecompileResults decompileResults = decompInterface.decompileFunction(targetFunction,
                                                                                  30,
                                                                                  monitor);
            HighFunction highTargetFunction = decompileResults.getHighFunction();
            List<HighVariable> variableList = getHighParameters(highTargetFunction);

            for (int parameterNumTarget = 0; parameterNumTarget < variableList.size();
                 parameterNumTarget++) {
                HighVariable highVariable = variableList.get(parameterNumTarget);
                Varnode[] instances = highVariable.getInstances();
                for (Varnode varnodeTarget : instances) {
                    Iterator<PcodeOp> pcodeOpIterator = varnodeTarget.getDescendants();
                    while (pcodeOpIterator.hasNext()) {
                        PcodeOp pcodeOp = pcodeOpIterator.next();
                        // TODO Work with CALLIND functions
                        // TODO Work with LOAD
                        // TODO Work with CAST
                        if (pcodeOp.getOpcode() == PcodeOp.CALL) {
                            Varnode[] inputs = pcodeOp.getInputs();
                            Address addressFunction = inputs[0].getAddress();
                            if (!addressFunction.equals(sourceFunction.getEntryPoint())) {
                                continue;
                            }
                            for (int parameterNumSource = 0; parameterNumSource < inputs.length;
                                 parameterNumSource++) {
                                Varnode varnodeSource = inputs[parameterNumSource];
                                if (varnodeSource.equals(varnodeTarget)) {
                                    ParameterDependence parameterDependence =
                                            parameterDependencies.get(
                                                    parameterNumSource - 1);
                                    List<Integer> parameters =
                                            parameterDependence.getDestinationParameters();
                                    if (!parameters.contains(parameterNumTarget)) {
                                        parameters.add(parameterNumTarget);
                                    }
                                    parameterDependence.setDestinationParameters(parameters);
                                }
                            }
                        }
                    }
                }
            }
        } finally {
            decompInterface.dispose();
        }
        return parameterDependencies;
    }

    private List<HighVariable> getHighParameters(HighFunction highFunction) {
        List<HighVariable> highParameters = new ArrayList<>();

        if (highFunction == null) {
            ghidraScript.printerr("Can't get highFunction");
            return highParameters;
        }
        FunctionPrototype functionPrototype = highFunction.getFunctionPrototype();
        int numParams = functionPrototype.getNumParams();
        for (int i = 0; i < numParams; i++) {
            highParameters.add(functionPrototype.getParam(i));
        }
        return highParameters;
    }
}

class FunctionWithParams {
    private Function function;
    private List<ParameterDependence> parameters;

    FunctionWithParams(Function function) {
        this.function = function;
    }

    FunctionWithParams(Function function, List<ParameterDependence> parameters) {
        this.function = function;
        this.parameters = parameters;
    }

    Function getFunction() {
        return function;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        FunctionWithParams that = (FunctionWithParams) o;
        return Objects.equals(function, that.function) &&
               Objects.equals(parameters, that.parameters);
    }

    @Override
    public int hashCode() {
        return Objects.hash(function, parameters);
    }

    @Override
    public String toString() {
        return "FunctionWithParams{function=" + function + " ( " + function.getEntryPoint() +
               " ), parameters=" + parameters + '}';
    }
}

class ParameterDependence {
    private List<Integer> destinationParameters;

    ParameterDependence() {
        this.destinationParameters = new ArrayList<>();
    }

    List<Integer> getDestinationParameters() {
        return destinationParameters;
    }

    void setDestinationParameters(List<Integer> destinationParameters) {
        this.destinationParameters = destinationParameters;
    }

    @Override
    public String toString() {
        return "ParameterDependence{destinationParameters=" + destinationParameters + '}';
    }
}