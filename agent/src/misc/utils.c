#include <common.h>

/*!
 * @brief
 *  Hashing data
 *
 * @param String
 *  Data/String to hash
 *
 * @param Length
 *  size of data/string to hash.
 *  if 0 then hash data til null terminator is found.
 *
 * @return
 *  hash of specified data/string
 */
FUNC ULONG HashString(
    _In_ PVOID  String,
    _In_ SIZE_T Length
) {
    ULONG  Hash  = 5576;
    PUCHAR Ptr  = { 0 };
    UCHAR  Char = { 0 };

    if ( ! String ) {
        return 0;
    }

    Ptr  = ( ( PUCHAR ) String );

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr ) break;
        } else {
            if ( U_PTR( Ptr - U_PTR( String ) ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << 5 ) + Hash ) + Char;

        ++Ptr;
    } while ( TRUE );

    return Hash;
}

/*============================[ Memory ]============================*/

FUNC PVOID MemCopy( _Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

FUNC void MemZero( _Inout_ PVOID Destination, _In_ SIZE_T Size)
{
	PULONG Dest = (PULONG)Destination;
	SIZE_T Count = Size / sizeof(ULONG);

	while (Count > 0)
	{
		*Dest = 0;
		Dest++;
		Count--;
	}

	return;
}

FUNC INT MemCmp( 
	PVOID s1, 
	PVOID s2, 
	INT len
) {
    PUCHAR p = s1;
    PUCHAR q = s2;
    INT charCompareStatus = 0;

    if ( s1 == s2 ) {
        return charCompareStatus;
    }

    while (len > 0)
    {
        if (*p != *q)
        {
            charCompareStatus = (*p >*q)?1:-1;
            break;
        }
        len--;
        p++;
        q++;
    }
    return charCompareStatus;
}

FUNC PVOID MemSet( void* Destination, int Value, size_t Size )
{
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}

/*============================[ Strings ]============================*/

FUNC SIZE_T WCharStringToCharString(_Inout_ PCHAR Destination, _In_ PWCHAR Source, _In_ SIZE_T MaximumAllowed)
{
	INT Length = (INT)MaximumAllowed;

	while (--Length >= 0)
	{
#pragma warning( push )
#pragma warning( disable : 4244)
		if (!(*Destination++ = *Source++))
			return MaximumAllowed - Length - 1;
#pragma warning( pop ) 
	}

	return MaximumAllowed - Length;
}

FUNC SIZE_T CharStringToWCharString(_Inout_ PWCHAR Destination, _In_ PCHAR Source, SIZE_T _In_ MaximumAllowed)
{
	INT Length = (INT)MaximumAllowed;

	while (--Length >= 0)
	{
		if (!(*Destination++ = *Source++))
			return MaximumAllowed - Length - 1;
	}

	return MaximumAllowed - Length;
}

FUNC SIZE_T StringLengthA(_In_ LPCSTR String)
{
	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

FUNC SIZE_T StringLengthW(_In_ LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

FUNC INT StringCompareA(_In_ LPCSTR String1, _In_ LPCSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}

FUNC INT StringNbrCmp(_In_ LPCSTR String1, _In_ LPCSTR String2, UINT32 Count) {
    for (UINT32 i = 0; i < Count; i++, String1++, String2++) {
        if (*String1 != *String2) {
            return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
        }

        if (*String1 == '\0') {
            return 0;
        }
    }

    return 0; // São iguais nos primeiros `Count` caracteres
}


FUNC INT StringCompareW(_In_ LPCWSTR String1, _In_ LPCWSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1);
}

FUNC void toLowerCaseChar(char* str) 
{
	while (*str) {
		if (*str >= 'A' && *str <= 'Z') {
			*str = *str + ('a' - 'A');
		}
		str++;
	}
}

FUNC void toUpperCaseChar(char* str) 
{
    while (*str) {
        if (*str >= 'a' && *str <= 'z') {
            *str = *str - ('a' - 'A');
        }
        str++;
    }
}


FUNC WCHAR toLowerCaseWchar(WCHAR ch)
{
	if (ch >= L'A' && ch <= L'Z') {
		return ch + (L'a' - L'A');
	}
	return ch;
}

FUNC PCHAR StringCopyA( _Inout_ PCHAR String1, _In_ LPCSTR String2 )
{
	PCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

FUNC PWCHAR StringCopyW( _Inout_ PWCHAR String1, _In_ LPCWSTR String2 )
{
	PWCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

FUNC WCHAR StringConcatW(_Inout_ PWCHAR String, _In_ LPCWSTR String2)
{
	StringCopyW(&String[StringLengthW(String)], String2);

	return (WCHAR)String;
}

FUNC PCHAR StringConcatA(_Inout_ PCHAR String, _In_ LPCSTR String2)
{
	StringCopyA(&String[StringLengthA(String)], String2);

	return String;
}

FUNC BOOL   IsStringEqual ( _In_ LPCWSTR Str1, _In_ LPCWSTR Str2 )
{
	WCHAR	lStr1	[MAX_PATH],
			lStr2	[MAX_PATH];

	int		len1	= StringLengthW(Str1),
			len2	= StringLengthW(Str2);

	int		i		= 0,
			j		= 0;

	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	for (i = 0; i < len1; i++){
		lStr1[i] = (WCHAR)toLowerCaseWchar(Str1[i]);
	}
	lStr1[i++] = L'\0'; // null terminating


	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)toLowerCaseWchar(Str2[j]);
	}
	lStr2[j++] = L'\0'; // null terminating


	if (StringCompareW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}

FUNC void InitUnicodeString( _Out_ PUNICODE_STRING UsStruct, _In_opt_ PCWSTR Buffer) 
{
	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = StringLengthW(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}

FUNC ULONG Random32() {
    UINT32 Seed = 0;

    _rdrand32_step(&Seed);

    return Seed;
}

FUNC ULONG RandomNumber32( VOID )
{
	BLACKOUT_INSTANCE
    ULONG Seed = 0;

    Seed = Instance()->Win32.GetTickCount();
    Seed = Instance()->Win32.RtlRandomEx( &Seed );
    Seed = Instance()->Win32.RtlRandomEx( &Seed );
    Seed = ( Seed % ( LONG_MAX - 2 + 1 ) ) + 2;

    return Seed % 2 == 0 ? Seed : Seed + 1;
}