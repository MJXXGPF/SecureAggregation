.code
o_swap proc
   test rcx,rcx
   
   mov r10,[r8] ;y->r10 200
  
   mov r9,[rdx] ;x->r9 100
   
   mov r11,r9 ;x->r11 100
   
   cmovnz r9,r10 ;x=y
   cmovnz r10,r11 ;y=x
     
   mov [rdx],r9
   mov [r8],r10
   
   ret

o_swap endp
end

; 指令解释
; mov dest,src
; cmovnz dest,src 前面test的结果是1才进行操作