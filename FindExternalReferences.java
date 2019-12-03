//Find all functions, which addresses contains in external programs, then create
//external functions and set external references.
//@author saruman9
//@category References.External
//@keybinding ctrl 5
//@menupath
//@toolbar

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.ProjectData;
import ghidra.framework.store.LockException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.VersionException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class FindExternalReferences extends GhidraScript {

    private HashMap<String, List<MemoryBlock>> intersectMemMap = new HashMap<>();
    private boolean isCancelled = false;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            Msg.showError(this,
                    null,
                    "Error",
                    "This script should be run from a tool with open program.");
            return;
        }

        ExternalManager externalManager = currentProgram.getExternalManager();
        String[] libraryNames = externalManager.getExternalLibraryNames();
        if (libraryNames.length == 0) {
            Msg.showInfo(this, null, "Info", "Not found external programs.");
            isCancelled = true;
            return;
        }

        List<Program> librariesProgram = new ArrayList<>();

        try {
            for (String libraryName : libraryNames) {
                if (monitor.isCancelled() || isCancelled) {
                    return;
                }
                Library library = externalManager.getExternalLibrary(libraryName);
                String libraryPath = library.getAssociatedProgramPath();
                if (libraryPath == null) {
                    printf("WARNING! You should set path for external library '%s'.\n", libraryName);
                    continue;
                }
                ProjectData projectData = state.getProject().getProjectData();
                DomainFile libraryFile = projectData.getFile(libraryPath);
                if (libraryFile == null) {
                    printf("WARNING! Domain file '%s' not found.\n", libraryPath);
                    continue;
                }
                Program libraryProgram = createLibraryProgram(libraryFile);
                if (libraryProgram == null) {
                    printf("WARNING! Can't get program for external library '%s'.\n", libraryPath);
                } else {
                    if (isExistReferences(new AddressSet(
                            libraryProgram.getMinAddress(),
                            libraryProgram.getMaxAddress()))) {
                        librariesProgram.add(libraryProgram);
                    }
                }
            }

            selectIntersections(librariesProgram);

            checkIntersections();
            if (isCancelled) {
                return;
            }

            createMemoryMaps();
            if (isCancelled || monitor.isCancelled()) {
                return;
            }

            findAndCreateExternalSymbols(librariesProgram);
            if (isCancelled) {
                return;
            }
        } finally {
            for (Program libraryObject : librariesProgram) {
                if (libraryObject != null) {
                    libraryObject.release(this);
                }
            }
        }
    }

    private boolean isExistReferences(AddressSetView addressSet) {
        AddressIterator addressIterator = currentProgram
                .getReferenceManager()
                .getReferenceDestinationIterator(addressSet, true);
        return addressIterator.hasNext();
    }

    private void createMemoryMaps() {
        boolean isShownWarning = false;
        for (Map.Entry<String, List<MemoryBlock>> intersect : intersectMemMap.entrySet()) {
            Memory memory = currentProgram.getMemory();
            List<MemoryBlock> memoryBlocks = intersect.getValue();
            int index = 0;
            for (MemoryBlock memoryBlock : memoryBlocks) {
                if (!isExistReferences(new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd()))) {
                    continue;
                }
                String name = String.format("%s_%d", intersect.getKey(), index);
                try {
                    MemoryBlock newMemoryBlock = memory.createUninitializedBlock(name,
                            memoryBlock.getStart(),
                            memoryBlock.getSize(),
                            false);
                    newMemoryBlock.setExecute(memoryBlock.isExecute());
                    newMemoryBlock.setWrite(memoryBlock.isWrite());
                    newMemoryBlock.setSourceName("External References resolver");
                    newMemoryBlock.setComment("NOTE: This block is artificial and is used" +
                            " to make external references work correctly");
                } catch (DuplicateNameException
                        | AddressOverflowException e) {
                    Msg.showError(this, null, "Error of creating memory block", e);
                    isCancelled = true;
                    return;
                } catch (LockException e) {
                    // TODO: Move the checking over memory blocks creation
                    if (!isShownWarning) {
                        boolean bContinue = askYesNo("Without exclusive check out",
                                "You don't have exclusive check out. " +
                                        "Only existed artificial memory blocks will be analyzed!\n" +
                                        "Exclusive check out required for first run of the script. " +
                                        "Do you want to continue analysis?");
                        if (!bContinue) {
                            monitor.cancel();
                            return;
                        }

                        isShownWarning = true;
                    }
                }
                // Ignore if memory already exist
                // TODO: Resolve partial overlapping
                catch (MemoryConflictException ignored) {
                }
                index += 1;
            }
        }
    }

    private void findAndCreateExternalSymbols(List<Program> librariesProgram) throws CancelledException {
        // Memory blocks and symbols should be sorted by address
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        for (MemoryBlock memoryBlock : currentProgram.getMemory().getBlocks()) {
            String sourceName = memoryBlock.getSourceName();
            if (sourceName != null && sourceName.equals("External References resolver")) {
                SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);
                AddressRange addressRange = new AddressRangeImpl(memoryBlock.getStart(), memoryBlock.getEnd());
                for (Symbol currentSymbol : symbolIterator) {
                    if (isCancelled) {
                        return;
                    }
                    if (addressRange.contains(currentSymbol.getAddress())) {
                        createExternalSymbols(currentSymbol, librariesProgram);
                    }
                }
            }
        }

        // Delete external symbols without references
        ExternalManager externalManager = currentProgram.getExternalManager();
        SymbolIterator symbolExternalIterator = symbolTable.getExternalSymbols();
        while (symbolExternalIterator.hasNext()) {
            Symbol symbol = symbolExternalIterator.next();
            ExternalLocation externalLocation = externalManager.getExternalLocation(symbol);
            if (externalLocation.isFunction()) {
                if (symbol.getReferenceCount() == 0) {
                    symbol.delete();
                }
            } else {
                if (externalLocation.getDataType() == null) {
                    symbol.delete();
                }
            }
        }
    }

    private void createExternalSymbols(Symbol symbolTarget, List<Program> librariesProgram) throws CancelledException {
        Address addressTarget = symbolTarget.getAddress();
        String pathnameLibrary = null;
        Program programLibrary = null;

        for (Map.Entry<String, List<MemoryBlock>> entry : intersectMemMap.entrySet()) {
            for (MemoryBlock memoryBlock : entry.getValue()) {
                if (memoryBlock.contains(addressTarget)) {
                    pathnameLibrary = entry.getKey();
                    break;
                }
            }
        }
        if (pathnameLibrary == null) {
            printf("%s:%s not found.\n", symbolTarget.getName(), addressTarget);
            return;
        }
        for (Program program : librariesProgram) {
            if (program.getDomainFile().getPathname().equals(pathnameLibrary)) {
                programLibrary = program;
                break;
            }
        }
        if (programLibrary == null) {
            printf("WARNING! Program not found!\n");
            return;
        }

        SymbolTable symbolTableLibrary = programLibrary.getSymbolTable();
        Symbol[] symbolsLibrary = symbolTableLibrary.getSymbols(addressTarget);
        for (Symbol symbolLibrary : symbolsLibrary) {
            if (monitor.isCancelled() || isCancelled) {
                return;
            }
            Reference[] referencesTarget = symbolTarget.getReferences(monitor);
            if (referencesTarget.length == 0) {
                continue;
            }
            RefType refType = referencesTarget[0].getReferenceType();
            // TODO: Add more types
            if (refType.isCall() || refType.isJump()) {
                createExternalFunction(symbolTarget, symbolLibrary);
            } else if (refType.isData()) {
                createExternalData(symbolTarget, symbolLibrary);
            }

            // Delete error bookmarks with "Bad Instruction" category
            BookmarkManager bookmarkManagerTarget = currentProgram.getBookmarkManager();
            for (Reference reference : referencesTarget) {
                bookmarkManagerTarget.removeBookmarks(new AddressSet(reference.getFromAddress()),
                        "Error",
                        "Bad Instruction",
                        monitor);
            }
        }
    }

    private void createExternalData(Symbol symbolTarget, Symbol symbolLibrary) {
        Program programLibrary = symbolLibrary.getProgram();
        DomainFile domainFileLibrary = programLibrary.getDomainFile();
        Address addressLibrary = symbolLibrary.getAddress();
        Listing listingLibrary = programLibrary.getListing();
        String nameSymbolLibrary = symbolLibrary.getName();
        Data dataLibrary = listingLibrary.getDataAt(addressLibrary);
        if (dataLibrary == null) {
            BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
            String message = String.format("Unable to resolve data at %s", symbolLibrary.getAddress());
            bookmarkManager.setBookmark(symbolTarget.getAddress(),
                    "Warning",
                    "Bad data",
                    message);
            return;
        }
        DataType dataTypeLibrary = dataLibrary.getDataType();

        Address addressTarget = symbolTarget.getAddress();
        Listing listingTarget = currentProgram.getListing();
        ExternalManager externalManagerTarget = currentProgram.getExternalManager();

        // Create external data
        try {
            ExternalLocation externalLocation = externalManagerTarget.addExtLocation(
                    domainFileLibrary.getName(),
                    nameSymbolLibrary,
                    addressLibrary,
                    SourceType.IMPORTED);
            externalLocation.setDataType(dataTypeLibrary);
        } catch (InvalidInputException | DuplicateNameException e) {
            Msg.showError(this, null, "Error of creating external data symbol", e.getMessage());
            isCancelled = true;
            return;
        }
        if (symbolTarget.getSource() == SourceType.USER_DEFINED) {
            return;
        }

        // Create symbol
        try {
            symbolTarget.setNameAndNamespace(nameSymbolLibrary,
                    symbolLibrary.getParentNamespace(),
                    SourceType.IMPORTED);
        } catch (DuplicateNameException | CircularDependencyException | InvalidInputException e) {
            Msg.showError(this, null, "Error of creating external data symbol", e.getMessage());
            isCancelled = true;
            return;
        }

        // Create data
        try {
            listingTarget.createData(addressTarget, dataTypeLibrary);
        } catch (CodeUnitInsertionException ignored) {
        }

        // Set comment with annotations
        // TODO: Find more idiomatic way for external data
        String comment = String.format("%s:{@program \"%s@%s\"}",
                dataLibrary.getValue(),
                domainFileLibrary.getPathname(),
                addressLibrary);
        listingTarget.setComment(addressTarget, CodeUnit.REPEATABLE_COMMENT, comment);
    }

    private void createExternalFunction(Symbol symbolTarget, Symbol symbolLibrary) {
        Address addressLibrary = symbolLibrary.getAddress();
        Function functionLibrary = symbolLibrary
                .getProgram()
                .getFunctionManager()
                .getFunctionAt(addressLibrary);
        FunctionManager functionManagerTarget = currentProgram.getFunctionManager();
        Address addressTarget = symbolTarget.getAddress();

        if (functionLibrary != null) {
            Function functionTarget = functionManagerTarget.getFunctionAt(addressTarget);
            if (functionTarget == null) {
                try {
                    functionTarget = functionManagerTarget.createFunction(functionLibrary.getName(),
                            addressTarget,
                            new AddressSet(addressTarget),
                            SourceType.IMPORTED);
                } catch (InvalidInputException | OverlappingFunctionException e) {
                    Msg.showError(this, null, "Error of creating function", e);
                    isCancelled = true;
                    return;
                }
            }
            try {
                ExternalLocation externalLocation = currentProgram.getExternalManager()
                        .addExtFunction(symbolLibrary.getProgram().getDomainFile().getName(),
                                symbolLibrary.getName(),
                                addressLibrary,
                                SourceType.IMPORTED);
                functionTarget.setThunkedFunction(externalLocation.getFunction());
            } catch (DuplicateNameException | InvalidInputException e) {
                Msg.showError(this, null, "Error of creating external location", e);
                isCancelled = true;
                return;
            }

            String callingConventionName = functionLibrary.getCallingConventionName();
            Parameter returnFunctionLibrary = functionLibrary.getReturn();
            Function.FunctionUpdateType updateType = Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS;
            SourceType sourceType = SourceType.IMPORTED;
            Parameter[] parameters = functionLibrary.getParameters();
            List<Parameter> newParameters = new ArrayList<>();
            for (Parameter parameter : parameters) {
                try {
                    Parameter newParam = new ParameterImpl(parameter, currentProgram);
                    newParam.setDataType(parameter.getDataType(), sourceType);
                    newParam.setName(parameter.getName(), sourceType);
                    newParameters.add(newParam);
                } catch (InvalidInputException | DuplicateNameException e) {
                    Msg.showError(this, null, "Error of changing SourceType", e);
                    isCancelled = true;
                    return;
                }
            }

            String nameFunction = functionLibrary.getName();
            String callFixup = functionLibrary.getCallFixup();
            boolean hasCustomVariableStorage = functionLibrary.hasCustomVariableStorage();
            boolean isInline = functionLibrary.isInline();
            boolean hasNoReturn = functionLibrary.hasNoReturn();
            int stackPurgeSize = functionLibrary.getStackPurgeSize();
            boolean hasVarArgs = functionLibrary.hasVarArgs();

            try {
                functionTarget.setName(nameFunction, sourceType);
                functionTarget.updateFunction(callingConventionName,
                        returnFunctionLibrary,
                        newParameters,
                        updateType,
                        true,
                        sourceType);
                functionTarget.setCallFixup(callFixup);
                functionTarget.setCustomVariableStorage(hasCustomVariableStorage);
                functionTarget.setInline(isInline);
                functionTarget.setNoReturn(hasNoReturn);
                functionTarget.setStackPurgeSize(stackPurgeSize);
                functionTarget.setVarArgs(hasVarArgs);
            } catch (DuplicateNameException | InvalidInputException e) {
                Msg.showError(this, null, "Error of updating function", e);
                isCancelled = true;
            }
        }
    }

    private void checkIntersections() {
        List<Pair<String, MemoryBlock>> memoryBlocks = new ArrayList<>();
        for (Map.Entry<String, List<MemoryBlock>> entry : intersectMemMap.entrySet()) {
            for (MemoryBlock memoryBlock : entry.getValue()) {
                memoryBlocks.add(new Pair<>(entry.getKey(), memoryBlock));
            }
        }

        for (int i = 0; i < memoryBlocks.size(); i++) {
            for (int j = i + 1; j < memoryBlocks.size(); j++) {
                Pair<String, MemoryBlock> memoryBlockFirst = memoryBlocks.get(i);
                Pair<String, MemoryBlock> memoryBlockSecond = memoryBlocks.get(j);
                AddressRange addressRangeFirst = new AddressRangeImpl(memoryBlockFirst.second.getStart(),
                        memoryBlockFirst.second.getEnd());
                AddressRange addressRangeSecond = new AddressRangeImpl(memoryBlockSecond.second.getStart(),
                        memoryBlockSecond.second.getEnd());
                AddressRange intersect = addressRangeFirst.intersect(addressRangeSecond);
                if (intersect != null) {
                    isCancelled = true;
                    String message =
                            String.format("%s intersects %s (%s).",
                                    memoryBlockFirst.first,
                                    memoryBlockSecond.first,
                                    intersect);
                    Msg.showError(this, null, "Intersect error", message);
                    return;
                }
            }
        }
    }

    private void selectIntersections(List<Program> programs) throws CancelledException {
        for (int i = 0; i < programs.size(); i++) {
            Program programFirst = programs.get(i);
            String pathnameFirst = programFirst.getDomainFile().getPathname();
            Address addressMinFirst = programFirst.getMinAddress();
            Address addressMaxFirst = programFirst.getMaxAddress();
            AddressRange addressRangeFirst = new AddressRangeImpl(addressMinFirst, addressMaxFirst);
            for (int j = i + 1; j < programs.size(); j++) {
                Program programSecond = programs.get(j);
                Address addressMinSecond = programSecond.getMinAddress();
                Address addressMaxSecond = programSecond.getMaxAddress();
                AddressRange addressRangeSecond = new AddressRangeImpl(addressMinSecond, addressMaxSecond);

                AddressRange intersect = addressRangeFirst.intersect(addressRangeSecond);
                if (intersect != null) {
                    askIntersections(programFirst);
                    askIntersections(programSecond);
                }
            }
            if (!intersectMemMap.containsKey(pathnameFirst)) {
                Memory memoryFirst = programFirst.getMemory();
                MemoryBlock[] memoryBlocksFirst = memoryFirst.getBlocks();
                List<MemoryBlock> memoryBlocksListFirst = Arrays.asList(memoryBlocksFirst);
                intersectMemMap.put(pathnameFirst, memoryBlocksListFirst);
            }
        }
    }

    private void askIntersections(Program program) throws CancelledException {
        String pathname = program.getDomainFile().getPathname();
        if (!intersectMemMap.containsKey(pathname)) {
            Memory memory = program.getMemory();
            List<MemoryBlock> memoryBlocks = Arrays.asList(memory.getBlocks());
            List<String> memoryBlocksStrings = memoryBlocks
                    .stream()
                    .map(memoryBlock -> String
                            .format("%s (%s)",
                                    memoryBlock.getName(),
                                    new AddressRangeImpl(memoryBlock.getStart(), memoryBlock.getEnd())))
                    .collect(Collectors.toList());
            List<MemoryBlock> memoryBlocksChoice = askChoices("Choose segments",
                    pathname,
                    memoryBlocks,
                    memoryBlocksStrings);
            intersectMemMap.put(pathname, memoryBlocksChoice);
        }
    }

    private Program createLibraryProgram(DomainFile libraryFile) {
        DomainObject libraryObject = null;
        try {
            libraryObject = libraryFile.getImmutableDomainObject(this,
                    DomainFile.DEFAULT_VERSION,
                    monitor);
            if (!(libraryObject instanceof Program)) {
                return null;
            }
        } catch (VersionException e) {
            Msg.showError(this, null, "Version Exception", e.getMessage());
            isCancelled = true;
        } catch (IOException e) {
            Msg.showError(this, null, "IO Exception", e.getMessage());
            isCancelled = true;
        } catch (CancelledException e) {
            monitor.cancel();
        }
        return (Program) libraryObject;
    }
}
