#!/usr/bin/env python3

# This script attempts to decrypt obfucated Codesys V3 ELF binaries.
# The binaries contain a decryptor stub that XOR the whole .text section during
# startup. The `known_binaries` dict contains information of binaries we
# successfully decrypted using this script. It needs a few pointers to XOR
# tables, fixups and regions it shouldn't touch when decrypting the ELF.
#
# The script attempts to create a deobfuscated ELF file which can be run on the
# target just like the encrypted versions. Also a few patches can be applied
# by the script to remove annoyances like anti-debug measures
#
# If you want to add support for another version, we suggest you get one of the
# supported binaries, load it into IDA or Ghidra and then figure out what the
# pointers mean and then add a new dict entry for your target binary and change
# the pointers to your needs. It's pretty obvious how the obfuscation works.
# Then, after deobfuscating the binary, track down what the patches do and change
# these pointers as well to match your binary.

import sys
import argparse
import hashlib
import struct
import io
from elftools.elf.elffile import ELFFile

known_binaries = {
    "1c522c6abbfed83dd682e0b0d4af17b4a87bbca4": {
        "name": "Codesys 3.5.15.10 PFC200",
        "xor1_table": 0x0878A058,
        "xor2_table": 0x08789058,
        "no_touchy": [
            { "start": 0x08050000, "end": 0x0805003C }, #start
            { "start": 0x0805003C, "end": 0x08050060 }, #gmon_start
            
            { "start": 0x08050098, "end": 0x080500D8 }, #FIXME: some unknown init stuff
            { "start": 0x08050100, "end": 0x08050138 }, #FIXME: more unknown init stuff

            { "start": 0x08623B10, "end": 0x08623B90 }, #decrypt_main

            { "start": 0x083DDD70, "end": 0x083DDD78 }, #j___libc_start_main
            { "start": 0x083DDF00, "end": 0x083DDF08 }, #j___gmon_start__
            { "start": 0x086E5A18, "end": 0x086E5A7C }, #__libc_csu_init
            { "start": 0x086E5E68, "end": 0x086E5E70 }, #j_.init_proc
            { "start": 0x086E6220, "end": 0x086E6228 }, #j_mprotect
        ],
        "patches": [
            # jump to OEP address in R0 instead of the decryption routine
            { "addr": 0x08623B7C, "value": b"\x30\xff\x2f\xe1" },

            # remove the ptrace anti-debug
            { "addr": 0x086237A0, "value": b"\x08\x00\x00\xea" },
            { "addr": 0x08623800, "value": b"\x2a\x00\x00\xea" },

            # remove the code which exits if some CommCycleHook
            # in SysTaskOSHookFunction wasn't running for the last 60 seconds
            # Patches out the check if 60s passed in SysTaskWaitInterval
            { "addr": 0x086D860C, "value": b"\x06\x00\x00\xea" },
        ]
    },

    "b7761575d7f298423d0908117caf764b7b09bdce": {
        "name": "Codesys 3.5.15.10 Raspberry Pi",
        "xor1_table": 0x088CA1C4,
        "xor2_table": 0x088C91C4,
        "no_touchy": [
            { "start": 0x08050000, "end": 0x0805003C }, #start
            { "start": 0x0805003C, "end": 0x08050060 }, #gmon_start
            
            { "start": 0x08050098, "end": 0x080500D8 }, #FIXME: some unknown init stuff
            { "start": 0x08050100, "end": 0x08050138 }, #FIXME: more unknown init stuff

            { "start": 0x0874CE50, "end": 0x0874CECC }, #decrypt_main

            { "start": 0x08431A30, "end": 0x08431A38 }, #j___libc_start_main
            { "start": 0x08807CE0, "end": 0x08807D40 }, #__libc_csu_init
            { "start": 0x08808190, "end": 0x08808198 }, #j_.init_proc
            { "start": 0x088084E8, "end": 0x088084F0 }, #j_mprotect
        ],
        "patches": [
            # jump to OEP address in R0 instead of the decryption routine
            { "addr": 0x0874CEB8, "value": b"\x30\xff\x2f\xe1" },

            # remove the ptrace anti-debug
            { "addr": 0x0874CACC, "value": b"\x08\x00\x00\xea" },
            { "addr": 0x0874CB2C, "value": b"\x2f\x00\x00\xea" },

            # remove the code which exits if some CommCycleHook
            # in SysTaskOSHookFunction wasn't running for the last 60 seconds
            # Patches out the check if 60s passed in SysTaskWaitInterval
            { "addr": 0x088013B8, "value": b"\x06\x00\x00\xea" },
        ]
    },

    "cfc2425c5e91a6267b5c42a6b0910b0b2368ce37": {
        "name": "Codesys 3.5.15.10 Beaglebone",
        "xor1_table": 0x08562564,
        "xor2_table": 0x08561564,
        "no_touchy": [
            { "start": 0x08050000, "end": 0x08050030 }, #start
            { "start": 0x08050030, "end": 0x08050054 }, #gmon_start
            
            { "start": 0x08050078, "end": 0x080500A4 }, #FIXME: some unknown init stuff
            { "start": 0x080500BC, "end": 0x080500DC }, #FIXME: more unknown init stuff

            { "start": 0x081523B0, "end": 0x0815240C }, #decrypt_main

            { "start": 0x083560B8, "end": 0x083560C0 }, #j___libc_start_main
            { "start": 0x083560B0, "end": 0x083560B8 }, #j___gmon_start__
            { "start": 0x085398D4, "end": 0x085398DC }, #j_.init_proc
            { "start": 0x08355D98, "end": 0x08355DA0 }, #j_mprotect

            { "start": 0x08539504, "end": 0x08539544 }, #__libc_csu_init
        ],
        "patches": [
            # jump to OEP address in R0 instead of the decryption routine
            { "addr": 0x081523FC, "value": b"\x80\x47\x00\xbf" },

            # remove the ptrace anti-debug
            { "addr": 0x08152124, "value": b"\x0d\xe0" },
            { "addr": 0x0815216E, "value": b"\x41\xe0" },

            # remove the code which exits if some CommCycleHook
            # in SysTaskOSHookFunction wasn't running for the last 60 seconds
            # Patches out the check if 60s passed in SysTaskWaitInterval
            { "addr": 0x08534BF6, "value": b"\x0b\xe0" },
        ]
    },

    "1e0a48b81483181b3a20b9c09b072c53f4122838": {
        "name": "Codesys 3.5.15.10 Linux x86_64",
        "xor1_table": 0x087ED660,
        "xor2_table": 0x087EC660,
        "no_touchy": [
            { "start": 0x08050000, "end": 0x0805002B }, #start
            { "start": 0x08050070, "end": 0x080500B2 },
            { "start": 0x08050100, "end": 0x08050130 },


            { "start": 0x083D3E40, "end": 0x083D3F00 }, #callback
            { "start": 0x083D3F00, "end": 0x083D3F65 }, #main

            { "start": 0x087A2330, "end": 0x087A2395 }, #init
            { "start": 0x087A23A0, "end": 0x087A23A2 }, #fini
        ],
        "patches": [
            # jump to OEP address in RDI instead of the decryption routine
            { "addr": 0x083D3F59, "value": b"\xff\xd7\x90\x90\x90" },

            # remove the ptrace anti-debug
            { "addr": 0x083D3B07, "value": b"\xeb\x17" },
            { "addr": 0x083D3B3E, "value": b"\xe9\x8b\x00\x00\x00" },

            # remove the code which exits if some CommCycleHook
            # in SysTaskOSHookFunction wasn't running for the last 60 seconds
            # Patches out the check if 60s passed in SysTaskWaitInterval
            { "addr": 0x0879D2D4, "value": b"\xeb\x1f" },

            # remove the call to mmap which remaps .text sections RWX
            # we don't need that anymore because we already decrypted the
            # binary
            { "addr": 0x083D3F4D, "value": b"\x90\x90\x90\x90\x90" },
        ]
    },
}


def is_no_touch_region(fileinfo, addr):
    no_touchy = fileinfo["no_touchy"]
    for r in no_touchy:
        if r["start"] <= addr < r["end"]:
            return True
    
    return False


def get_file_sha1(file):
    file.seek(0)
    sha1Hash = hashlib.sha1(file.read())
    file.seek(0)
    return sha1Hash.hexdigest()


def fileoffset_by_virtaddr(elf, addr):
    for s in elf.iter_segments():
        if s.header.p_type == "PT_LOAD":
            startaddr = s.header.p_vaddr
            endaddr = startaddr + s.header.p_filesz #use file size here, we are only interested in stuff which is actually in the binary

            if startaddr <= addr < endaddr:
                virt_offset = addr - startaddr
                fileoffset = virt_offset + s.header.p_offset
                return fileoffset

    return None


def segment_and_offset_by_virtaddr(elf, addr):
    for s in elf.iter_segments():
        if s.header.p_type == "PT_LOAD":
            startaddr = s.header.p_vaddr
            endaddr = startaddr + s.header.p_filesz #use file size here, we are only interested in stuff which is actually in the binary

            if startaddr <= addr < endaddr:
                return s.data(), addr - startaddr

    return None


def get_xor_table(elf, addr, num_dwords):
    s, o = segment_and_offset_by_virtaddr(elf, addr)

    fmtstr = "<" + "I"*num_dwords
    data = s[o:o + struct.calcsize(fmtstr)]

    tbl = list(struct.unpack(fmtstr, data))
    return tbl


def decrypt_two_words(curword, nextword, xor1_table, xor2_table):
	for i in range(17, 1, -1):
		v2 = curword ^ xor1_table[i]

		byte0 = v2 & 0xff
		byte1 = (v2 >> 8) & 0xff
		byte2 = (v2 >> 16) & 0xff
		byte3 = (v2 >> 24) & 0xff

		curword = nextword ^ ((((xor2_table[byte3] + xor2_table[byte2 + 256] & 0xFFFFFFFF) ^ xor2_table[byte1 + 512]) + xor2_table[byte0 + 768]) & 0xFFFFFFFF)
		nextword = v2

	new_curword = nextword ^ xor1_table[0]
	new_nextword = curword ^ xor1_table[1]

	return new_curword, new_nextword


def iterate_two_dwords(bytestring):
    #assert(len(bytestring) % 8 == 0)

    for i in range(len(bytestring)//8):
        yield struct.unpack("<II", bytestring[i*8:i*8+8])


def main():
    parser = argparse.ArgumentParser(description='Decrypt Codesys 3.5 binary')
    parser.add_argument('binary', help='The file to decrypt', type=argparse.FileType('rb+'))

    args = parser.parse_args()

    h = get_file_sha1(args.binary)
    if not h in known_binaries.keys():
        print("Unknown binary, can't decrypt")
        sys.exit(1)
    
    fileinfo = known_binaries[h]
    print(f"Decrypting file '{fileinfo['name']}'")

    original_file = args.binary
    decrypted_file = io.BytesIO(original_file.read())
    original_file.seek(0)

    decrypted_elffile = ELFFile(decrypted_file)

    # get the magic xor table
    xor1_table = get_xor_table(decrypted_elffile, fileinfo["xor1_table"], 18)
    xor2_table = get_xor_table(decrypted_elffile, fileinfo["xor2_table"], 1024)


    # apply the fixups
    fixup_section = decrypted_elffile.get_section_by_name('.fixup')
    fixup_data = fixup_section.data()[:-4]  #last 4 bytes are garbage?
    for d in iterate_two_dwords(fixup_data):
        if d[0] == 0:
            break

        print(f"Applying fixup 0x{d[0]:08x} -> 0x{d[1]:08x}")
        patch_offset = fileoffset_by_virtaddr(decrypted_elffile, d[0])
        decrypted_file.seek(patch_offset)
        decrypted_file.write(struct.pack("<I", d[1]))


    # start decryption
    text_section = decrypted_elffile.get_section_by_name(".text")
    text_offset = fileoffset_by_virtaddr(decrypted_elffile, text_section.header.sh_addr)
    #text_data = text_section.data()
    #assert(len(text_data) % 8 == 0)

    # Read text section + what is behind, length needs to be a multiple of 8
    text_len_aligned_up = (text_section.data_size + 8 - 1) & ~(8 - 1)
    original_file.seek(text_offset)
    text_data = original_file.read(text_len_aligned_up)

    decrypted_file.seek(text_offset)
    original_file.seek(text_offset)

    addr = text_section.header.sh_addr
    for d in iterate_two_dwords(text_data):
        dec1, dec2 = decrypt_two_words(d[0], d[1], xor1_table, xor2_table)
        orig1, orig2 = struct.unpack("<II", original_file.read(8))

        decrypted_file.write(struct.pack("<I", orig1 if is_no_touch_region(fileinfo, addr) else dec1))
        addr += 4

        decrypted_file.write(struct.pack("<I", orig2 if is_no_touch_region(fileinfo, addr) else dec2))
        addr += 4


    # apply patches
    for patch in fileinfo["patches"]:
        patch_offset = fileoffset_by_virtaddr(decrypted_elffile, patch["addr"])
        decrypted_file.seek(patch_offset)
        decrypted_file.write(patch["value"])


    # write the decrypted file
    decrypted_file.seek(0)
    original_file.seek(0)
    original_file.truncate()
    original_file.write(decrypted_file.read())


    # done
    original_file.close()
    decrypted_file.close()


if __name__ == '__main__':
    main()
