# Ghidra scripts

<!-- markdown-toc start - Don't edit this section. Run M-x markdown-toc-refresh-toc -->
**Table of Contents**

- [Ghidra scripts](#ghidra-scripts)
    - [Installing scripts](#installing-scripts)
    - [External references search](#external-references-search)
        - [Instruction](#instruction)
    - [Set entry points in selection](#set-entry-points-in-selection)
        - [Instruction](#instruction-1)
    - [Remove all references](#remove-all-references)
        - [From address](#from-address)
        - [To address](#to-address)
        - [Instruction](#instruction-2)
    - [FindMultipleLabels](#findmultiplelabels)
        - [Instruction](#instruction-3)
    - [FindNeededFunctions](#findneededfunctions)
        - [Instruction](#instruction-4)
    - [BasicBlockModelExample](#basicblockmodelexample)
        - [Instruction](#instruction-5)
    - [Example of parsing PE header](#example-of-parsing-pe-header)
        - [Instruction](#instruction-6)
    - [Printing ASM/PCode/PCodeHigh/C](#printing-asmpcodepcodehighc)
        - [Instruction](#instruction-7)
    - [Printing PCode](#printing-pcode)
        - [Instruction](#instruction-8)
    - [Set default calling convention for functions in Selection](#set-default-calling-convention-for-functions-in-selection)
        - [Instruction](#instruction-9)
    - [Find references of the field of a structure](#find-references-of-the-field-of-a-structure)
        - [Instruction](#instruction-10)

<!-- markdown-toc end -->

## Installing scripts

Please read `${GHIDRA_HOME}/docs/GhidraClass/Intermediate/Scripting_withNotes.html` and *Ghidra Script Manager* section of Help.

## External references search

| :information_source: | [Source file](./FindExternalReferences.java) |
| -----                | -----                                        |

Script finds all references to the functions and data from all external programs (shared libraries), then creates additional memory blocks and transfer all info about functions (name, signature, additional info) and data (name, also create comment with value and annotation with link to external program). A source type of symbols will be `IMPORTED`, a source type of parameters will be `IMPORTED`, if parameters of the original function don't have `DEFAULT` source type, otherwise a source type will be `DEFAULT` too.

### Instruction

1. Import binary file.
2. Analyze it.
3. Add needed external programs (see Figure 1):
    - `Window → External Programs`
    - `Add External Program Name`
    - `Set External Name Association`

    ![External programs](images/external_programs.png)
    > Figure 1. Added External Programs
    
4. Run the script (choose memory blocks if needed, see Figure 2).

    ![Choose segments](images/choose_segments.png)
    > Figure 2. Choose needed memory blocks

| Before                         | After                        |
| -----                          | -----                        |
| ![Before](./images/before.png) | ![After](./images/after.png) |
> Figure 3. Before and after running the script

| :information_source: | You can run the script multiple times. |
| -----                | -----                                  |

:warning: **Warning:**

>>>

- script will not change user-defined symbols (you should delete user-defined symbols, if you want to import information from external symbols);

- you should look symbols with `Global` namespace (not external) for finding xrefs to external functions and data (see Figure 4).

>>>

![In memory located symbols](images/in_memory_located_symbols.png)
> Figure 4. Symbol with `Global` Namespace have true references

## Set entry points in selection

| :information_source: | [Source file](./SetEntryPointsInSelection.java) |
| -----                | -----                                           |

Script set all labels (functions) in selection as Entry Point.

### Instruction

1. Select needed functions through Functions window.
2. Run the script.

## Remove all references

Use for clearing of the analysis results.

### From address

| :information_source: | [Source file](./RemoveAllReferencesFromAddress.java) |
| -----                | -----                                                |

### To address

| :information_source: | [Source file](./RemoveAllReferencesToAddress.java) |
| -----                | -----                                              |

### Instruction

1. Select addresses or set the cursor to one address.
2. Run the script.

## FindMultipleLabels

Print all symbols (and their addresses) with multiple labels. Maybe useful for Version Tracking session.

| :information_source: | [Source file](./FindMultipleLabels.java) |
| -----                | -----                                    |

### Instruction

1. Run the script.

## FindNeededFunctions

| :information_source: | [Source file](./FindNeededFunctions.java) |
| -----                | -----                                     |

Find all functions with parameters, which will be dereferenced.

### Instruction

1. Run the script.

## BasicBlockModelExample

| :information_source: | [Source file](./BasicBlockModelExample.java) |
| -----                | -----                                        |

Prints all basic blocks of the program (change the source code for printing an interesting information) with sources and destinations information (other basic blocks).

### Instruction

1. Run the script.

## Example of parsing PE header

| :information_source: | [Source file](./GetEntryPoints.java) |
| -----                | -----                                |

The script parses PE header and print an entry point address (address of a valid function) from optional header.

### Instruction

1. Run the script.

## Printing ASM/PCode/PCodeHigh/C

| :information_source: | [Source file](./PrintCodeHeadless.java) |
| -----                | -----                                   |

The script should be used in headless mode. May be useful for debugging of a decompiler and writing Sleigh code. The script can print ASM code, PCode, PCodeHigh, decompiling C code (use arguments).

:warning: **Warning:**

>>>

- the script can damage the target project, you should to watch the arguments for GhidraHeadless.

>>>

### Instruction

See comments in the script file.

## Printing PCode

| :information_source: | [Source file](./PrintPCode.java) |
| -----                | -----                            |

The script prints high PCode to console. May be useful for debugging of a decompiler. You should known, that the AST of high PCode and the AST of any varnode may be different in a scope of the same function.

### Instruction

1. Run the script.

## Set default calling convention for functions in Selection

| :information_source: | [Source file](./SetDefaultCallingConvInSelection.java) |
| -----                | -----                                                  |

The script set default convention (see Language ID) for all functions in the selection.

### Instruction

1. Select needed functions. I recommends do it through Functions window, where you can sort and filter functions.

1. Run the script.

## Find references of the field of a structure

| :information_source: | [Source file](./FindRefsField.java) |
| -----                | -----                               |

The script finds all references to the field of a structure.

### Instruction

1. Set cursor at the field of a structure in the Decompiler window.
1. Run the script.

