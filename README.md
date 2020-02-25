## SimTLS
This project is a demo to simulate *nix system TLS access under windows using exception and inline hook.


### How to build

mkdir build  && cd build

cmake .. -DASMJIT_BUILD_X86=true -DASMJIT_STATIC=true -T llvm -A x64

