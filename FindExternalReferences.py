# Find all functions, which addresses contains in external programs, then create external functions
# and set external references.
# @category: References.External

from ghidra.app.script import GhidraState
from ghidra.framework.model import DomainFile
from ghidra.program.database import ProgramContentHandler
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import VersionException


def processDomainFile(domainFile):
    if not ProgramContentHandler.PROGRAM_CONTENT_TYPE == domainFile.getContentType():
        return  # skip non-Program files
    if domainFile.isVersioned() and not domainFile.isCheckedOut():
        println("WARNING! Skipping versioned file - not checked-out: " + domainFile.getPathname())
    program = None
    consumer = java.lang.Object()
    try:
        domainObject = domainFile.getImmutableDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor)
        processProgram(domainObject)
    except VersionException:
        println("ERROR! Failed to process file due to upgrade issue: " + domainFile.getPathname())
    finally:
        if program is not None:
            program.release(consumer)

def processProgram(program):
    externalLibraryName = program.getDomainFile().getName()
    println("Processing: " + program.getDomainFile().getPathname())
    monitor.setMessage("Processing: " + externalLibraryName)

    try:
        # TODO use symbols from `Exports`
        newFunctionManager = program.getFunctionManager()
        newFunctions = newFunctionManager.getFunctions(True)

        currentExternalManager = currentProgram.getExternalManager()

        newFunctionCount = newFunctionManager.getFunctionCount()
        monitor.setMaximum(newFunctionManager.getFunctionCount())
        for counterFunction, function in enumerate(newFunctions):
            monitor.checkCanceled()
            monitor.incrementProgress(1)
            monitor.setMessage("Processing: " + externalLibraryName + ", " + str(counterFunction) +
                               "/" + str(newFunctionCount) + " functions")
            currentAllSymbols = currentProgram.getSymbolTable().getAllSymbols(True)
            for symbol in currentAllSymbols:
                if symbol.getAddress() == function.getEntryPoint():
                    # TODO Create bookmark
                    externalLocation = currentExternalManager.addExtFunction(externalLibraryName,
                                                                             function.getName(),
                                                                             symbol.getAddress(),
                                                                             SourceType.USER_DEFINED)
                    externalFunction = externalLocation.getFunction()

                    newCallingConvention = function.getCallingConventionName()
                    newReturnValue = function.getReturn()
                    newUpdateType = Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS
                    newSource = SourceType.USER_DEFINED
                    newParameters = function.getParameters()
                    externalFunction.updateFunction(newCallingConvention, newReturnValue,
                                                    newUpdateType, True, newSource, newParameters)

                    currentReferenceManager = currentProgram.getReferenceManager()
                    for reference in currentReferenceManager.getReferencesTo(symbol.getAddress()):
                        currentReferenceManager.addExternalReference(reference.getFromAddress(),
                                                                     externalLibraryName,
                                                                     function.getName(),
                                                                     function.getEntryPoint(),
                                                                     SourceType.USER_DEFINED,
                                                                     reference.getOperandIndex(),
                                                                     reference.getReferenceType())
    except Exception as err:
        printerr("ERROR! Exception occurred while processing file: " +
                 program.getDomainFile().getPathname())
        printerr("       " + str(err))


externalManager = currentProgram.getExternalManager()
libraryNames = externalManager.getExternalLibraryNames()
project = state.getProject()
projectData = project.getProjectData()
rootFolder = projectData.getRootFolder()
for name in libraryNames:
    file = rootFolder.getFile(name)
    processDomainFile(file)
