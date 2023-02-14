# This script attempts to decrypt the Codesys binary for the WAGO PFC200 directly
# in IDA. To use this script with other binaries, a few constants need to be
# changed to find the XOR tables, fixups etc.
#
# Run it from within IDA using Alt + F7
#
# Binary: Codesys 3.5.15.10 PFC200
# SHA1 hash of binary: 1c522c6abbfed83dd682e0b0d4af17b4a87bbca4

import ida_bytes

MAGIC_XOR_TABLE1 = 0x0878A058
MAGIC_XOR_TABLE2 = 0x08789058
FIXUPS = 0x087C91EC

START = 0x08050000

def get_magic_xor_table1(idx):
	return ida_bytes.get_dword(MAGIC_XOR_TABLE1 + idx * 4)

def get_magic_xor_table2(idx):
	return ida_bytes.get_dword(MAGIC_XOR_TABLE2 + idx * 4)

def decrypt_two_words(curword, nextword):
	for i in range(17, 1, -1):
		v2 = curword ^ get_magic_xor_table1(i)

		byte0 = v2 & 0xff
		byte1 = (v2 >> 8) & 0xff
		byte2 = (v2 >> 16) & 0xff
		byte3 = (v2 >> 24) & 0xff

		curword = nextword ^ ((((get_magic_xor_table2(byte3) + get_magic_xor_table2(byte2 + 256) & 0xFFFFFFFF) ^ get_magic_xor_table2(byte1 + 512)) + get_magic_xor_table2(byte0 + 768)) & 0xFFFFFFFF)
		nextword = v2

	new_curword = nextword ^ get_magic_xor_table1(0)
	new_nextword = curword ^ get_magic_xor_table1(1)

	return new_curword, new_nextword

def decrypt(start):
	ptr = start
	while ptr < 0x86E66E0 and ptr < 0x86E63A0:
	#while ptr < 0x08050008:
		curword = ida_bytes.get_dword(ptr)
		nextword = ida_bytes.get_dword(ptr + 4)
		curword, nextword = decrypt_two_words(curword, nextword)
		ida_bytes.patch_dword(ptr, curword)
		ida_bytes.patch_dword(ptr + 4, nextword)
		ptr += 8

def apply_fixups():
	for i in range(256):
		dest = ida_bytes.get_dword(FIXUPS + i*8)
		new_val = ida_bytes.get_dword(FIXUPS + i*8 + 4)
		if dest == 0: break
		print("Applying fixup at 0x{:08x}: 0x{:08x} -> 0x{:08x}".format(FIXUPS + i*8, dest, new_val))
		ida_bytes.patch_dword(dest, new_val)

print("Applying fixups")
apply_fixups()

print("Decrypting .text")
decrypt(START)
#OIP = 08623740
