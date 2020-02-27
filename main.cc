#include <Zydis/Zydis.h>
#include <asmjit/asmjit.h>

#include <cassert>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <vector>
#include <windows.h>

// address range
constexpr size_t kMaxAddrRange = 0x40000000;

static thread_local int pseudoVar = 15;
static ZydisDecoder gDecoder{};
static ZydisFormatter gFormatter{};

/**
 * ref https://chao-tic.github.io/blog/2018/12/25/tls
 * @brief Simulate TLS access in *nix system. This function should trigger an
 * access violation exception
 *
 * @return uint64_t
 */
uint64_t tlsAccess()
{
    uint64_t a = 37;
    // Case 2: TLS variable externally defined in a shared object but used in a
    // executable
    asm("mov $0xfffffffffffffffc, %rax");
    asm("mov %fs:(%rax), %rax");

    asm("movq %%rax, %0" : "=r"(a));

    // just make a rip relative instruction to validate my rellocation.
    goto msg;
msg:
    printf("a=%d\n", a);

    return a;
}

/**
 * @brief A function stub for accessing real TLS variable.
 *
 * @param offset
 * @return uint64_t
 */
uint64_t readTLSOffset(int64_t offset)
{
    if (offset == 0xfffffffffffffffc) {
        return pseudoVar;
    }

    return 0;
}

// ref:
// https://www.codeproject.com/Articles/44326/MinHook-The-Minimalistic-x-x-API-Hooking-Libra

/**
 * @brief Search backward from pAddress to find a free memory region for
 * allocating.
 *
 * @param pAddress base address
 * @param pMinAddr lower bound
 * @param dwAllocationGranularity memory allocation granularity
 * @return void*
 */
static void *findPrevFreeRegion(void *pAddress,
                                void *pMinAddr,
                                DWORD dwAllocationGranularity)
{
    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    // Round down to the allocation granularity.
    tryAddr -= tryAddr % dwAllocationGranularity;

    // Start from the previous allocation granularity multiply.
    tryAddr -= dwAllocationGranularity;

    while (tryAddr >= (ULONG_PTR)pMinAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPVOID)tryAddr, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_FREE)
            return (LPVOID)tryAddr;

        if ((ULONG_PTR)mbi.AllocationBase < dwAllocationGranularity)
            break;

        tryAddr = (ULONG_PTR)mbi.AllocationBase - dwAllocationGranularity;
    }

    return nullptr;
}

/**
 * @brief Search forward from pAddress to find a free memory region for
 * allocating.
 *
 * @param pAddress base address
 * @param pMaxAddr upper bound
 * @param dwAllocationGranularity memory allocation granularity
 * @return void*
 */
static void *findNextFreeRegion(void *pAddress,
                                void *pMaxAddr,
                                DWORD dwAllocationGranularity)
{
    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    // Round down to the allocation granularity.
    tryAddr -= tryAddr % dwAllocationGranularity;

    // Start from the next allocation granularity multiply.
    tryAddr += dwAllocationGranularity;

    while (tryAddr <= (ULONG_PTR)pMaxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPVOID)tryAddr, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_FREE)
            return (LPVOID)tryAddr;

        tryAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;

        // Round up to the next allocation granularity.
        tryAddr += dwAllocationGranularity - 1;
        tryAddr -= tryAddr % dwAllocationGranularity;
    }

    return nullptr;
}

struct MemoryRangeInfo {
    size_t minAddress;
    size_t maxAddress;
    DWORD allocationGranularity;
};

/**
 * @brief Get upper bound , lower bound and granularity.
 *
 * @param targetAddr target address
 * @return MemoryRangeInfo
 */
static MemoryRangeInfo getUsableMemoryRange(void *targetAddr)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    size_t minAddr = reinterpret_cast<size_t>(si.lpMinimumApplicationAddress);
    size_t maxAddr = reinterpret_cast<size_t>(si.lpMaximumApplicationAddress);

    size_t addr = reinterpret_cast<size_t>(targetAddr);

    if ((addr > kMaxAddrRange) && (addr - kMaxAddrRange >= minAddr)) {
        minAddr = addr - kMaxAddrRange;
    }

    if (addr + kMaxAddrRange <= maxAddr) {
        maxAddr = addr + kMaxAddrRange;
    }

    maxAddr -= kMaxAddrRange - 1;

    return {minAddr, maxAddr, si.dwAllocationGranularity};
}

static void *allocPrevAvailableMemoryBlock(void *pAlloc, size_t minAddr, DWORD grad)
{
    void *allocAddress = nullptr;
    do {
        pAlloc =
            findPrevFreeRegion(pAlloc, reinterpret_cast<void *>(minAddr), grad);
        if (pAlloc) {
            allocAddress =
                VirtualAlloc(pAlloc, 0x1000, MEM_RESERVE | MEM_COMMIT,
                             PAGE_EXECUTE_READWRITE);
        }
    } while (pAlloc != nullptr && allocAddress == nullptr &&
             reinterpret_cast<size_t>(pAlloc) > minAddr);

    return allocAddress;
}

static void *allocNextAvailableMemoryBlock(void *pAlloc, size_t maxAddr, DWORD grad)
{
    void *allocAddress = nullptr;
    do {
        pAlloc =
            findNextFreeRegion(pAlloc, reinterpret_cast<void *>(maxAddr), grad);
        if (pAlloc) {
            allocAddress =
                VirtualAlloc(pAlloc, 0x1000, MEM_RESERVE | MEM_COMMIT,
                             PAGE_EXECUTE_READWRITE);
        }
    } while (pAlloc != nullptr && allocAddress == nullptr &&
             reinterpret_cast<size_t>(pAlloc) < maxAddr);

    return allocAddress;
}

/**
 * @brief Allocate a memory address within +-2Gb boundary.
 *
 * @param targetAddr
 * @return void*  nullptr if failed
 */
void *allocNearbyPage(void *targetAddr)
{
    auto [minAddr, maxAddr, grad] = getUsableMemoryRange(targetAddr);

    void *pAlloc       = targetAddr;
    void *allocAddress = nullptr;

    allocAddress = allocPrevAvailableMemoryBlock(pAlloc, minAddr, grad);
    if (allocAddress == nullptr) {
        allocAddress = allocNextAvailableMemoryBlock(pAlloc, maxAddr, grad);
    }

    return allocAddress;
}

int initZyDis()
{
    ZydisDecoderInit(&gDecoder, ZYDIS_MACHINE_MODE_LONG_64,
                     ZYDIS_ADDRESS_WIDTH_64);

    ZydisFormatterInit(&gFormatter, ZYDIS_FORMATTER_STYLE_INTEL);

    return 0;
}

void printInstruction(ZydisDecodedInstruction const &inst, uint64_t addr)
{
    char buffer[256] = {};
    ZydisFormatterFormatInstruction(&gFormatter, &inst, buffer, 256, addr);

    std::cout << buffer << std::endl;
}

bool getRIPRelativeDisplacement(ZydisDecodedInstruction const &inst,
                                int32_t *value)
{
    auto count = inst.operand_count;
    bool found = false;

    for (int i = 0; i < count && !found; i++) {
        auto &op    = inst.operands[i];
        auto opType = inst.operands[i].type;

        switch (opType) {
        case ZYDIS_OPERAND_TYPE_MEMORY: {
            if (op.mem.base == ZYDIS_REGISTER_RIP &&
                op.mem.disp.has_displacement) {
                *value = op.mem.disp.value;
                found  = true;
            }
        } break;

        case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
            if (op.imm.is_relative) {
                *value = op.imm.value.s;
                found  = true;
            }
        } break;

		case ZYDIS_OPERAND_TYPE_REGISTER: {
		} break;
		

        default: {
            std::cout << "unhandled operand type: " << opType << std::endl;
			printInstruction(inst, 0);
        } break;
        }
    }

    return found;
}

bool substitudeInstructionValue(uint8_t *instruction,
                                uint8_t len,
                                int oldValue,
                                int newValue)
{
    uint8_t *p      = reinterpret_cast<uint8_t *>(&oldValue);
    uint8_t *newVal = reinterpret_cast<uint8_t *>(&newValue);

    std::string_view srcStr{(char *)(instruction), len};
    std::string_view pat{(char *)(p), 4};

    auto idx = srcStr.find(pat);

    if (idx != std::string_view::npos) {
        std::copy(newVal, newVal + 4, &instruction[idx]);
        return true;
    }

    return false;
}

struct TLSAccessInfo {
    uint8_t length;
    uint8_t registerOperand;
    bool isImmDisplacement;

    union {
        int32_t imm;
        struct {
            uint8_t reg;
            int64_t offset;
        } reg;
    } disp;

    void *instructionAddress;
    PEXCEPTION_POINTERS exceptionPtr;
};

/**
 * @brief Checks if an instruction is TLS access
 *
 * @param address instruction address
 * @param info info
 * @return true
 * @return false
 */
bool isTLSAccess(void *address, TLSAccessInfo *info)
{
    ZydisDecodedInstruction inst{};

    ZydisDecoderDecodeBuffer(&gDecoder, address, 15, &inst);

    if (inst.mnemonic != ZYDIS_MNEMONIC_MOV) {
        return false;
    }

    if (inst.operand_count != 2) {
        return false;
    }

    bool isFSAccess    = false;
    uint8_t regOperand = 0;

    for (int i = 0; i < inst.operand_count; i++) {
        auto &op = inst.operands[i];

        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
            op.mem.segment == ZYDIS_REGISTER_FS) {

            isFSAccess = true;
            if (op.mem.base == ZYDIS_REGISTER_NONE) {
                info->isImmDisplacement = true;
                info->disp.imm          = op.mem.disp.value;
            } else {
                info->isImmDisplacement = false;
                info->disp.reg.reg      = op.mem.base;
                if (op.mem.disp.has_displacement) {
                    info->disp.reg.offset = op.mem.disp.value;
                }
            }
        }

        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            regOperand = op.reg.value;
        }
    }

    if (!isFSAccess) {
        return false;
    }

    info->length             = inst.length;
    info->registerOperand    = regOperand;
    info->instructionAddress = address;
    return true;
}

int countBytesToCopy(void *target,
                      int bytesNeeded,
                      std::vector<ZydisDecodedInstruction> *insts)
{
    int length    = 0;
    auto &instVec = *insts;

    auto targetInst = reinterpret_cast<uint8_t *>(target);

    do {
        instVec.emplace_back();
        auto &inst = instVec.back();
        ZydisDecoderDecodeBuffer(&gDecoder, &targetInst[length], 15, &inst);
        length += inst.length;
    } while (length < bytesNeeded);

    return length;
}

static int fixPatchSpot(void *buffer,
                        void *src,
                        std::vector<ZydisDecodedInstruction> &instVec)
{
    auto address = reinterpret_cast<uint8_t *>(src);
    auto destBuf = reinterpret_cast<uint8_t *>(buffer);

    int length = 0;
    for (auto &inst : instVec) {
        memcpy(&destBuf[length], &address[length], inst.length);

        int offset = 0;
        bool res   = getRIPRelativeDisplacement(inst, &offset);
        if (res) {
            // patch instruction
            substitudeInstructionValue(&destBuf[length], inst.length, offset,
                                       (int)(address - destBuf + offset));
        }

        length += inst.length;
    }

    return length;
}

static bool generateJumpStub(void *buffer, int fsOffset, size_t *sizeOut)
{
    using namespace asmjit;

    JitRuntime rt{};
    CodeHolder code{};

    code.init(rt.codeInfo());
    x86::Assembler assembler{&code};

    assembler.mov(x86::rax, reinterpret_cast<uint64_t>(readTLSOffset));
    assembler.push(x86::rcx);
    assembler.mov(x86::rcx, fsOffset);
    assembler.call(x86::rax);
    assembler.pop(x86::rcx);

    auto buf    = code.sectionById(0)->buffer();
    auto target = reinterpret_cast<uint8_t *>(buffer);

    std::copy(buf.begin(), buf.end(), target);

    *sizeOut = buf.size();
    return true;
}

static bool
generateJumpBack(void *bufferAddr, TLSAccessInfo const &info, int offset)
{
    using namespace asmjit;

    // jmp <somewhere>
    uint8_t instTemplate[] = {0xe9, 0x00, 0x00, 0x00, 0x00};

    auto buffer = reinterpret_cast<uint8_t *>(bufferAddr);
    auto target = reinterpret_cast<uint8_t *>(info.instructionAddress) + offset;

    int jmpDisplacement       = (target - buffer) - 5;
    *(int *)(&instTemplate[1]) = jmpDisplacement;

    std::copy(instTemplate, instTemplate + sizeof(instTemplate), buffer);

    return true;
}

bool makeJumpStub(void *targetAddress, TLSAccessInfo const &info)
{
    constexpr int kJmpStubLength = 8;

    std::vector<ZydisDecodedInstruction> decodedInsts{};
    decodedInsts.reserve(5);

    int64_t fsOffset = 0;

    if (info.isImmDisplacement) {
        fsOffset = info.disp.imm;
    } else {
        if (info.disp.reg.reg != ZYDIS_REGISTER_RAX) {
            // not supported currently
            assert(false);
        } else {
            fsOffset =
                info.exceptionPtr->ContextRecord->Rax + info.disp.reg.offset;
        }
    }

    auto buffer = reinterpret_cast<uint8_t *>(targetAddress);
    size_t ofs  = 0;

    auto tlsAccessAddr = reinterpret_cast<uint8_t *>(info.instructionAddress);
    generateJumpStub(buffer, fsOffset, &ofs);

    int owSize = info.length;
    if (info.length < kJmpStubLength) {
        int copySize =
            countBytesToCopy(tlsAccessAddr + info.length,
                              kJmpStubLength - info.length, &decodedInsts);

        fixPatchSpot(&buffer[ofs], tlsAccessAddr + info.length, decodedInsts);
        owSize += copySize;
        ofs += copySize;
    }

    generateJumpBack(&buffer[ofs], info, owSize);

    return true;
}

/**
 * @brief Calculate and patch 32bit jump instruction
 * 
 * @param from from
 * @param to to
 * @return true 
 * @return false 
 */
bool installPatch(void *from, void *to)
{
    auto targetAddr = reinterpret_cast<uint8_t *>(from);
    auto stubBuf = reinterpret_cast<uint8_t *>(to);

    uint64_t instBuf = 0x90909000000000e9;
    int addrOffset  = 0;
    addrOffset = (int)(stubBuf - targetAddr - 5);

    instBuf   = instBuf | ((addrOffset << 8) & 0x000000ffffffff00);
    DWORD op = 0;
    VirtualProtect(targetAddr, 1, PAGE_EXECUTE_READWRITE, &op);

    *(uint64_t *)targetAddr = instBuf;

    return true;
}

/**
 * @brief Path TLS access code when exception raises.
 *
 * @param info TLS access instruction info
 * @return true
 * @return false
 */
bool patchTLSAccess(TLSAccessInfo const *info)
{
    auto targetAddr = reinterpret_cast<uint8_t *>(info->instructionAddress);
    auto stubBuf =
        reinterpret_cast<uint8_t *>(allocNearbyPage(targetAddr));

    makeJumpStub(stubBuf, *info);
    installPatch(targetAddr, stubBuf);

    return true;
}

long __stdcall vectoredExceptionHandler(PEXCEPTION_POINTERS e)
{
    auto expAddr = e->ExceptionRecord->ExceptionAddress;
    TLSAccessInfo info{};

    if (!isTLSAccess(expAddr, &info)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    info.exceptionPtr = e;
    patchTLSAccess(&info);

    return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{
    initZyDis();

    AddVectoredExceptionHandler(TRUE,
                                reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(
                                    vectoredExceptionHandler));

    auto r = tlsAccess();
    std::cout << r << std::endl;

    return 0;
}