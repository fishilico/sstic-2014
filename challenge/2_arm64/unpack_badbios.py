#!/usr/bin/env python3
"""Unpack badbios.bin"""

import os.path
import arm64emu

curdir = os.path.dirname(__file__)
binname = os.path.join(curdir, 'badbios.bin')
disasm = os.path.join(curdir, 'badbios.bin.disasm')

# for each section, give size, VMA and file offset
SECTIONS = {
    'hdr': (0x10c, 0, 0),
    '.text': (0x48c, 0x1010c, 0x10c),
    '.rodata': (0x40, 0x10598, 0x598),
    '.data': (0x11f50, 0x21000, 0x1000),
}

# Create emulator
machine = arm64emu.ARM64LinuxEmu(
    disasm, program_name='badbios.bin', verbosity=arm64emu.VERBOSITY_SYSCALL)

# Map file
with open(binname, 'rb') as f:
    filedata = f.read()
    assert len(filedata) == 78000
    for name, sectinfo in SECTIONS.items():
        size, addr, fileoff = sectinfo
        machine.mem.load_mem(addr, filedata[fileoff:fileoff + size])

# Entry point
machine.branch(0x102cc)

# Run!
try:
    machine.run()
except arm64emu.OutPC as exc:
    print("Next instruction: 0x{:x}".format(exc.pc))

# Dump new mapped memory
with open(os.path.join(curdir, 'badbios-400000.bin'), 'wb') as f:
    f.write(machine.mem.zones[0x400000])
with open(os.path.join(curdir, 'badbios-500000.bin'), 'wb') as f:
    f.write(machine.mem.zones[0x500000])
