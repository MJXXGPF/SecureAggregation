.code
o_equal proc
        xor rax,rax
    cmp rcx,rdx
        sete al
    ret
o_equal endp
end