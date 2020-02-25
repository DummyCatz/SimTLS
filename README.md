## SimTLS
This project serves as a demo to simulate x86-64 *nix system TLS access under windows using exception and inline hook.
Only clang-cl/LLVM is supported.

### How to build
``` bash
git clone https://github.com/DummyCatz/SimTLS.git --recursive 
mkdir build && cd build 
cmake .. -DASMJIT_BUILD_X86=true -DASMJIT_STATIC=true -T llvm -A x64
```
