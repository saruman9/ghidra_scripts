# Ghidra scripts, plugins, etc

## Scripts

### External references search

[file](./FindExternalReferences.py)

Script find all references to the functions from all external programs (shared
libraries) and set external references, set name and prototype (signature) of
the functions.

**Warning:**

- if addresses of functions of external programs overlapped, then script will
use the function from last external program;

- script force rewrites name and prototype of functions now.

![Find external references](./find_external_references.gif)
