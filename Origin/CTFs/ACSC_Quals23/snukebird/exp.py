from pwn import *

r = remote('snukebird.chal.ctf.acsc.asia', 7441)
# r = process('./snukebird')

r.recvuntil("stage: ")
r.sendline("1")

commands = [
    "2wdssd",
    "3aaaa",
    "2dw",
    "3aaaa",
    "1wdddd",
    "3aaaaaw",
    "2ddddwdwwww",
    "1dddddddw",
    "2aaaaa",
    "1dwwwwaaaaaaaaaaaaaaaaw",
    "2aaaaaaaaaa",
    "3dddddwdddddwdddwdwdw",
    "2wdddddddddddddddssas",
    "3aaaaaaaaaa",
    "2aaaaawdddddwdwwaaaaaaawaaaaaaaa",
    "3aawaaaaaw",
    "2waw",
    "1ww"
]

for c in commands:
    for i in range(1, len(c)):
        r.sendline(c[i] + c[0])

r.recvuntil("stage: ")
r.sendline("2")

commands = [
    "1ddwddsdssasaaawaassdssddsddwdwddsddsddwddwwawaaawawaa",
    "1wawaasaaaasasasasasasasasasasasasasasasasasasas"
]

for c in commands:
    for i in range(1, len(c)):
        r.sendline(c[i] + c[0])

r.recvuntil("stage: ")
r.sendline("3")

commands = [
    "2ddddddddddddddd",
    "1ddddddddddddd",
    "2w",
    "1dwdwd"
] + ["2dw", "1wd"]*16 + ["1dd", "2dd"]

for c in commands:
    for i in range(1, len(c)):
        r.sendline(c[i] + c[0])
        
r.recvuntil("stage: ")
r.sendline("2")
commands = [
    "1ddwddsdssassdsddwdwdddwdwwaawaasasawawaasawaasaawww",
    "1ddddddddddddddddddddddwwaaaaaaaaaaaaaaaaaaaaaaaasssdddddddddddddddddddddddd",
    "1wddsdsddsddsdddwddssassaasaawawaasasaawaawwdwdddwdwwawaasaawww",
    "1ddddddddddddddddddddddwwaaaaaaaaaaaaaaaaaaaaaaaassssdddddddddddddddddddddddd",
    "1wddsdsddwdwddsddssassdssaasaawawaasasaawaawwawwddsdddwdwwawaasaawwwww",
    "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
]


for c in commands:
    for i in range(1, len(c)):
        r.sendline(c[i] + c[0])

        
r.interactive()
