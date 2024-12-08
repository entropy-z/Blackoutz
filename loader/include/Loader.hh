#ifndef LOADER_H
#define LOADER_H

#include <windows.h>

#include <Native.hh>

EXTERN_C int printf(PCSTR, ...);

namespace Win32 {

    namespace Api {
        template<typename Ret, typename... Args>
        class CallWrapper {
        public:
            static Ret Call(PSTR ModuleName, PSTR FunctionName, Args... args) {
                HMODULE Module = GetModuleHandleA(ModuleName);
                if (!Module) printf("[!] Failed to get module base\n");

                FARPROC Function = GetProcAddress(Module, FunctionName);
                if (!Function) printf("[!] Failed to get function base\n");

                auto Func = reinterpret_cast<Ret(*)(Args...)>(Function);
                return Func(args...);
            }
        };

        template<typename Ret, typename... Args>
        Ret Call(PSTR ModuleName, PSTR FunctionName, Args... args) {
            return CallWrapper<Ret, Args...>::Call(ModuleName, FunctionName, args...);
        }
    }

    namespace Memory {
        template<typename T>
        inline PVOID Copy(T* Dest, const T* Src, SIZE_T Size) {
            __builtin_memcpy(Dest, Src, Size);
            return Dest;
        }

        template<typename T>
        inline void Zero(T* Ptr, SIZE_T Size) {
            RtlSecureZeroMemory(Ptr, Size);
        }

        template<typename T>
        inline void Set(T* Dest, UCHAR Value, SIZE_T Size) {
            __stosb(reinterpret_cast<unsigned char*>(Dest), Value, Size);
        }

        inline PVOID Alloc(UINT64 Size) {
            return Win32::Api::Call<PVOID>("ntdll.dll", "RtlAllocateHeap", GetProcessHeap(), 0, Size);
        }

        inline PVOID ReAlloc(PVOID Ptr, UINT64 Size) {
            return Win32::Api::Call<PVOID>("ntdll.dll", "RtlReAllocateHeap", GetProcessHeap(), 0, Ptr, Size);
        }

        inline BOOL Free(PVOID Ptr, UINT64 Size) {
            Win32::Memory::Zero(static_cast<PBYTE>(Ptr), Size);
            return Win32::Api::Call<BOOL>("ntdll.dll", "RtlFreeHeap", GetProcessHeap(), 0, Ptr);
        }
    }

    namespace String {
        inline SIZE_T WCharStringToCharString(PCHAR Dest, PWCHAR Src, SIZE_T MaxAllowed) {
            SIZE_T Length = MaxAllowed;
            while (--Length > 0) {
                if (!(*Dest++ = static_cast<CHAR>(*Src++))) {
                    return MaxAllowed - Length - 1;
                }
            }
            return MaxAllowed - Length;
        }

        inline SIZE_T CharStringToWCharString(PWCHAR Dest, PCHAR Src, SIZE_T MaxAllowed) {
            SIZE_T Length = MaxAllowed;
            while (--Length > 0) {
                if (!(*Dest++ = static_cast<WCHAR>(*Src++))) {
                    return MaxAllowed - Length - 1;
                }
            }
            return MaxAllowed - Length;
        }

        inline SIZE_T LengthA(LPCSTR String) {
            LPCSTR End = String;
            while (*End) ++End;
            return End - String;
        }

        inline SIZE_T LengthW(LPCWSTR String) {
            LPCWSTR End = String;
            while (*End) ++End;
            return End - String;
        }

        inline INT CompareA(LPCSTR Str1, LPCSTR Str2) {
            while (*Str1 && (*Str1 == *Str2)) {
                ++Str1;
                ++Str2;
            }
            return static_cast<INT>(*Str1) - static_cast<INT>(*Str2);
        }

        inline INT CompareW(LPCWSTR Str1, LPCWSTR Str2) {
            while (*Str1 && (*Str1 == *Str2)) {
                ++Str1;
                ++Str2;
            }
            return static_cast<INT>(*Str1) - static_cast<INT>(*Str2);
        }

        inline void ToLowerCaseChar(PCHAR Str) {
            while (*Str) {
                if (*Str >= 'A' && *Str <= 'Z') {
                    *Str += ('a' - 'A');
                }
                ++Str;
            }
        }

        inline WCHAR ToLowerCaseWchar(WCHAR Ch) {
            return (Ch >= L'A' && Ch <= L'Z') ? Ch + (L'a' - L'A') : Ch;
        }

        inline PCHAR CopyA(PCHAR Dest, LPCSTR Src) {
            PCHAR p = Dest;
            while ((*p++ = *Src++));
            return Dest;
        }

        inline PWCHAR CopyW(PWCHAR Dest, LPCWSTR Src) {
            PWCHAR p = Dest;
            while ((*p++ = *Src++));
            return Dest;
        }

        inline void ConcatA(PCHAR Dest, LPCSTR Src) {
            CopyA(Dest + LengthA(Dest), Src);
        }

        inline void ConcatW(PWCHAR Dest, LPCWSTR Src) {
            CopyW(Dest + LengthW(Dest), Src);
        }

        inline BOOL IsStringEqual( LPCWSTR Str1, LPCWSTR Str2 ) {
            WCHAR TempStr1[MAX_PATH], TempStr2[MAX_PATH];
            SIZE_T Length1 = LengthW(Str1);
            SIZE_T Length2 = LengthW(Str2);

            if (Length1 >= MAX_PATH || Length2 >= MAX_PATH) return FALSE;

            for (SIZE_T i = 0; i < Length1; ++i) {
                TempStr1[i] = ToLowerCaseWchar(Str1[i]);
            }
            TempStr1[Length1] = L'\0';

            for (SIZE_T j = 0; j < Length2; ++j) {
                TempStr2[j] = ToLowerCaseWchar(Str2[j]);
            }
            TempStr2[Length2] = L'\0';

            return CompareW(TempStr1, TempStr2) == 0;
        }

        inline VOID InitUnicode(PUNICODE_STRING UnicodeString, PCWSTR Buffer) {
            if (Buffer) {
                SIZE_T Length = LengthW(Buffer) * sizeof(WCHAR);
                if (Length > 0xFFFC) Length = 0xFFFC;

                UnicodeString->Buffer = const_cast<PWSTR>(Buffer);
                UnicodeString->Length = static_cast<USHORT>(Length);
                UnicodeString->MaximumLength = static_cast<USHORT>(Length + sizeof(WCHAR));
            } else {
                UnicodeString->Buffer = nullptr;
                UnicodeString->Length = 0;
                UnicodeString->MaximumLength = 0;
            }
        }
    }
}

#endif // LOADER_H
