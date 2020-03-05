# libinjector
*Linux x64 - Shared library injection tool*

## Build
`g++ library_injector.cpp Utils.cpp TracedProcess.cpp -o library_injector -ldl`

## Run
`library_injector <process name> <library path>"`
