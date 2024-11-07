#include <windows.h>

#include <native.h>
#include <macros.h>

SIZE_T WCharStringToCharString(
    _Inout_ PCHAR Destination, 
    _In_    PWCHAR Source, 
    _In_    SIZE_T MaximumAllowed
) {
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

SIZE_T CharStringToWCharString(
    _Inout_ PWCHAR Destination, 
    _In_    PCHAR Source, 
    _In_    SIZE_T MaximumAllowed
) {
	INT Length = (INT)MaximumAllowed;

	while (--Length >= 0)
	{
		if (!(*Destination++ = *Source++))
			return MaximumAllowed - Length - 1;
	}

	return MaximumAllowed - Length;
}

SIZE_T StringLengthA(
	_In_ LPCSTR String
) {
	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

SIZE_T StringLengthW(
	_In_ LPCWSTR String
) {
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

INT StringCompareA(
	_In_ LPCSTR String1, 
	_In_ LPCSTR String2
) {
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}

INT StringCompareW(
	_In_ LPCWSTR String1, 
	_In_ LPCWSTR String2
) {
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1);
}

void toLowerCaseChar(
	char* str
) {
	while (*str) {
		if (*str >= 'A' && *str <= 'Z') {
			*str = *str + ('a' - 'A');
		}
		str++;
	}
}

WCHAR toLowerCaseWchar(
	WCHAR ch
) {
	if (ch >= L'A' && ch <= L'Z') {
		return ch + (L'a' - L'A');
	}
	return ch;
}

PCHAR StringCopyA( 
	_Inout_ PCHAR  String1, 
	_In_ 	LPCSTR String2
) {
	PCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

PWCHAR StringCopyW( 
	_Inout_ PWCHAR  String1, 
	_In_    LPCWSTR String2 
) {
	PWCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

WCHAR StringConcatW(
    _Inout_ PWCHAR  String, 
    _In_    LPCWSTR String2
) {
	StringCopyW(&String[StringLengthW(String)], String2);

	return (WCHAR)String;
}

PCHAR StringConcatA(
    _Inout_ PCHAR  String, 
    _In_    LPCSTR String2
) {
	StringCopyA(&String[StringLengthA(String)], String2);

	return String;
}

BOOL IsStringEqual( 
    _In_ LPCWSTR Str1, 
    _In_ LPCWSTR Str2 
) {
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

void InitUnicodeString( 
    _Out_    PUNICODE_STRING UsStruct, 
    _In_opt_ PCWSTR          Buffer
) {
	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = StringLengthW(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}

ULONG Random32(
	void
) {
    UINT32 Seed = 0;

    _rdrand32_step(&Seed);

    return Seed;
}
