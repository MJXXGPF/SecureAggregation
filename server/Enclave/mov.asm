.code
o_mov proc
        
    xor rbx, rbx
    mov rbx, rcx
    test rbx, rbx
    mov rax,[rdx]
    cmovnz rax, [r8]
    mov [r9],rax
    ret
    
o_mov endp
end