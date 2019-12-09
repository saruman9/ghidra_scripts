//Create function call graph
//@author saruman9
//@category Functions
//@keybinding ctrl 1
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.AcyclicCallGraphBuilder;
import ghidra.util.exception.CancelledException;
import ghidra.util.graph.AbstractDependencyGraph;
import ghidra.util.graph.DependencyGraph;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class FunctionCallGraph extends GhidraScript {
    @Override
    protected void run() throws Exception {
        FunctionIterator functionIterator = currentProgram.getFunctionManager()
                                                          .getFunctions(true);
        List<Function> functions = new ArrayList<>();
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            functions.add(function);
        }
        AcyclicCallGraphBuilder builder = new AcyclicCallGraphBuilder(currentProgram,
                                                                      functions,
                                                                      false
        );
        Function currentFunction = currentProgram.getFunctionManager()
                                                 .getFunctionContaining(currentAddress);
        AbstractDependencyGraph<Address> graph = builder.getDependencyGraph(monitor);
//        printf("%s\n", graph.getDependentValues(currentAddress));

        AcyclicCallGraphWithParamsBuilder builder1 = new AcyclicCallGraphWithParamsBuilder(
                currentProgram,
                currentFunction,
                this
        );
        AbstractDependencyGraph<FunctionWithParams> graph1 = builder1.getDependencyGraph(monitor);
//        printf("%s\n", graph1.getValues());
        FunctionWithParams first = (FunctionWithParams) graph1.getAllIndependentValues()
                                                              .toArray()[0];
//        println(first.toString());
//        println(graph1.getDependentValues(first).toString());
        println(graph1.getAllIndependentValues().toString());
    }
}

class AcyclicCallGraphWithParamsBuilder {
    private Program program;
    private Function functionRoot;
    // TODO Delete
    private GhidraScript ghidraScript;

    AcyclicCallGraphWithParamsBuilder(Program program,
                                      Function functionRoot,
                                      GhidraScript ghidraScript) {
        this.program = program;
        this.functionRoot = functionRoot;
        this.ghidraScript = ghidraScript;
    }

    AbstractDependencyGraph<FunctionWithParams> getDependencyGraph(TaskMonitor monitor) {
        AbstractDependencyGraph<FunctionWithParams> graph = new DependencyGraph<>();
        try {
            fillGraph(graph, functionRoot, new LinkedList<>(), monitor);
        } catch (CancelledException e) {
            return graph;
        }

        return graph;
    }

    private void fillGraph(AbstractDependencyGraph<FunctionWithParams> graph,
                           Function function,
                           Deque<Function> visitedFunctions,
                           TaskMonitor monitor) throws CancelledException {
        ghidraScript
                .println(String.format("Analyzed: %s (%s)", function, function.getEntryPoint()));
        ghidraScript.println(visitedFunctions.toString());
        if (visitedFunctions.contains(function)) {
            ghidraScript.println("Exist!");
            return;
        }
        visitedFunctions.push(function);
        FunctionManager functionManager = program.getFunctionManager();
        Symbol symbol = function.getSymbol();
        Reference[] references = symbol.getReferences(monitor);
        FunctionWithParams functionWithParams = new FunctionWithParams(function);
        if (graph.contains(functionWithParams)) {
            ghidraScript
                    .println(String.format("Contains %s (%s)", function, function.getEntryPoint()));
        }
        for (Reference reference : references) {
            monitor.checkCanceled();
            if (!reference.getReferenceType().isCall()) {
                continue;
            }
            Function functionReferenced = functionManager
                    .getFunctionContaining(reference.getFromAddress());
            if (functionReferenced == null) {
                ghidraScript
                        .printerr(String.format("Function error: %s", reference.getFromAddress()));
                continue;
            }
            FunctionWithParams referenceFunctionWithParams = new FunctionWithParams(
                    functionReferenced);

            graph.addDependency(referenceFunctionWithParams, functionWithParams);
            fillGraph(graph, functionReferenced, visitedFunctions, monitor);
        }
        ghidraScript.println(String.format("Finish: %s (%s)", function, function.getEntryPoint()));
        visitedFunctions.pop();
        ghidraScript.println(visitedFunctions.toString());
    }
}

class FunctionWithParams {
    private Function function;
    private ParametersDependence parameters;

    public FunctionWithParams(Function function) {
        this.function = function;
    }

    public FunctionWithParams(Function function, ParametersDependence parameters) {
        this.function = function;
        this.parameters = parameters;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FunctionWithParams that = (FunctionWithParams) o;
        return Objects.equals(function, that.function) &&
               Objects.equals(parameters, that.parameters);
    }

    @Override
    public int hashCode() {
        return Objects.hash(function, parameters);
    }

    public void setParameters(ParametersDependence parameters) {
        this.parameters = parameters;
    }

    @Override
    public String toString() {
        return "FunctionWithParams{" +
               "function=" + function + " ( " + function.getEntryPoint() + " )" +
               ", parameters=" + parameters +
               '}';
    }
}

class ParametersDependence {
    private int sourceParameter;
    private int[] destinationParameters;

    public ParametersDependence(int sourceParameter, int[] destinationParameters) {
        this.sourceParameter = sourceParameter;
        this.destinationParameters = destinationParameters;
    }
}
