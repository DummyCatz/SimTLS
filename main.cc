#include <asmjit.h>

#include <cstdint>
#include <iostream>
#include <cassert>
#include <windows.h>

// address range
constexpr size_t kMaxAddrRange = 0x40000000;

static thread_local int pseudoVar = 15;

/**
 * @brief Simulate TLS access in *nix system. This function should trigger an 
 * access violation exception
 * 
 * @return uint64_t
 */
uint64_t tlsAccess() 
{ 
    uint64_t a = 0;
    asm("mov %fs:0xfffffffffffffffc, %rax"); 
    asm("movq %%rax, %0" : "=r"(a));
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
    if (offset == 0xfffffffffffffffc)
    {
        return pseudoVar;
    } 

    return 0;
}

// ref: https://www.codeproject.com/Articles/44326/MinHook-The-Minimalistic-x-x-API-Hooking-Libra

/**
 * @brief Search backward from pAddress to find a free memory region for allocating.
 * 
 * @param pAddress base address
 * @param pMinAddr lower bound
 * @param dwAllocationGranularity memory allocation granularity
 * @return void* 
 */
static void *
findPrevFreeRegion(void *pAddress, void *pMinAddr, DWORD dwAllocationGranularity)
{
    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    // Round down to the allocation granularity.
    tryAddr -= tryAddr % dwAllocationGranularity;

    // Start from the previous allocation granularity multiply.
    tryAddr -= dwAllocationGranularity;

    while (tryAddr >= (ULONG_PTR)pMinAddr)
    {
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
 * @brief Search forward from pAddress to find a free memory region for allocating.
 * 
 * @param pAddress base address
 * @param pMaxAddr upper bound
 * @param dwAllocationGranularity memory allocation granularity
 * @return void* 
 */
static void *
findNextFreeRegion(void *pAddress, void *pMaxAddr, DWORD dwAllocationGranularity)
{
    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    // Round down to the allocation granularity.
    tryAddr -= tryAddr % dwAllocationGranularity;

    // Start from the next allocation granularity multiply.
    tryAddr += dwAllocationGranularity;

    while (tryAddr <= (ULONG_PTR)pMaxAddr)
    {
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

struct MemoryRangeInfo
{
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
MemoryRangeInfo getUsableMemoryRange(void *targetAddr)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    size_t minAddr = reinterpret_cast<size_t>(si.lpMinimumApplicationAddress);
    size_t maxAddr = reinterpret_cast<size_t>(si.lpMaximumApplicationAddress);

    size_t addr = reinterpret_cast<size_t>(targetAddr);

    if ((addr > kMaxAddrRange) && (addr - kMaxAddrRange >= minAddr))
    {
        minAddr = addr - kMaxAddrRange;
    }

    if (addr + kMaxAddrRange <= maxAddr)
    {
        maxAddr = addr + kMaxAddrRange;
    }

    maxAddr -= kMaxAddrRange - 1;

    return {minAddr, maxAddr, si.dwAllocationGranularity};
}

void *allocPrevAvailableMemoryBlock(void *pAlloc, size_t minAddr, DWORD grad)
{
    void *allocAddress = nullptr;
    do
    {
        pAlloc = findPrevFreeRegion(pAlloc, reinterpret_cast<void *>(minAddr), grad);
        if (pAlloc)
        {
            allocAddress = VirtualAlloc(pAlloc, 0x1000, MEM_RESERVE | MEM_COMMIT,
                                        PAGE_EXECUTE_READWRITE);
        }
    } while (pAlloc != nullptr &&
             allocAddress == nullptr && 
             reinterpret_cast<size_t>(pAlloc) > minAddr);

    return allocAddress;
}

void *allocNextAvailableMemoryBlock(void *pAlloc, size_t maxAddr, DWORD grad)
{
    void *allocAddress = nullptr;
    do
    {
        pAlloc = findNextFreeRegion(pAlloc, reinterpret_cast<void *>(maxAddr), grad);
        if (pAlloc)
        {
            allocAddress = VirtualAlloc(pAlloc, 0x1000, MEM_RESERVE | MEM_COMMIT,
                                        PAGE_EXECUTE_READWRITE);
        }
    } while (pAlloc != nullptr &&
             allocAddress == nullptr &&
             reinterpret_cast<size_t>(pAlloc) < maxAddr);

    return allocAddress;
}

/**
 * @brief Allocate a memory address within +-2Gb boundary.
 * 
 * @param targetAddr 
 * @return void*  nullptr if failed
 */
void *allocNearbyMemoryBlock(void *targetAddr)
{
    auto [minAddr, maxAddr, grad] = getUsableMemoryRange(targetAddr);

    void *pAlloc       = targetAddr;
    void *allocAddress = nullptr;

    allocAddress = allocPrevAvailableMemoryBlock(pAlloc, minAddr, grad);
    if (allocAddress == nullptr)
    {
        allocAddress = allocNextAvailableMemoryBlock(pAlloc, maxAddr, grad);
    }

    return allocAddress;
}

long __stdcall VEHHandler(void *e)
{
    // **The exception handler is not thread safe currently**
    using namespace asmjit;

    auto exp        = reinterpret_cast<PEXCEPTION_POINTERS>(e);
    auto targetAddr = exp->ExceptionRecord->ExceptionAddress;
    auto codeBuf = reinterpret_cast<uint8_t *>(allocNearbyMemoryBlock(targetAddr));

    assert(codeBuf != nullptr);

    // This address should be acquired from zydis disassmbler.
    int64_t offsetFromZydis = 0xfffffffffffffffc;

    JitRuntime rt{};
    CodeHolder code{};

    code.init(rt.codeInfo());
    x86::Assembler assembler{&code};

    // pop return address into rax and add it with 4
    assembler.pop(x86::rax);
    assembler.add(x86::rax, 4);
    assembler.push(x86::rax);
    
    assembler.mov(x86::rax, reinterpret_cast<uint64_t>(readTLSOffset));
    assembler.push(x86::rcx);
    assembler.mov(x86::rcx, offsetFromZydis);
    assembler.call(x86::rax);
    assembler.pop(x86::rcx);

    assembler.ret();

    auto buffer = code.sectionById(0)->buffer();
    auto size   = code.codeSize();

    for (size_t i = 0; i < size; i++)
    {
        codeBuf[i] = buffer[i];
    }

    // 8-byte instruction buffer
    // E8                  jmp
    // 00 00 00 00         imm
    // 90 90 90            3*nop

    uint64_t buf = 0x90909000000000e8;

    int addrOffset = 0;
    if (targetAddr > codeBuf)
    {
        addrOffset = (int)(-((size_t)targetAddr - (size_t)codeBuf) - 5);
    }
    else
    {
        addrOffset = (int)((size_t)codeBuf - (size_t)targetAddr) - 5;
    }

    buf = buf | ((addrOffset << 8) & 0x000000ffffffff00);

    DWORD op = 0;
    VirtualProtect(targetAddr, 1, PAGE_EXECUTE_READWRITE, &op);

    *(uint64_t *)targetAddr = buf;

    return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{
    AddVectoredExceptionHandler(
        TRUE, reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(VEHHandler));

    auto r = tlsAccess();

    std::cout << r << std::endl;

    return 0;
}