[BITS 64]
DEFAULT REL
EXTERN Entry

GLOBAL Start
GLOBAL StRipStart
GLOBAL StRipEnd

[SECTION .text$A]
    Start:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 020h
        call  Entry
        mov   rsp, rsi
        pop   rsi
        ret

    StRipStart:
        call StRipPtrStart
        ret

    StRipPtrStart:
        mov	rax, [rsp]
        sub rax, 0x1b  
        ret           

[SECTION .text$E]
    StRipEnd:
        call StRetPtrEnd
        ret

    StRetPtrEnd:
        mov rax, [rsp]
        add	rax, 0xb  
        ret            

[SECTION .text$P]
    SymStardustEnd:
        DB 'B', 'L', 'A', 'C', 'K', '-', 'E', 'N', 'D'