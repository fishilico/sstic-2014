#!/usr/bin/env python3
"""Unpack badbios.bin"""

import arm64emu
import os.path
import traceback

curdir = os.path.dirname(__file__)
disasm = os.path.join(curdir, 'badbios-400000.bin.disasm')

# Create emulator
machine = arm64emu.ARM64LinuxEmu(
    disasm, program_name='badbios.bin', verbosity=arm64emu.VERBOSITY_SYSCALL)

# Map memory zones
for addr in (0x400000, 0x500000):
    filename = os.path.join(curdir, 'badbios-{:x}.bin'.format(addr))
    with open(filename, 'rb') as f:
        machine.mem.load_mem(addr, f.read())

# Define entry point
machine.branch(0x400514)

# Run!
try:
    machine.run()
except Exception:
    print(traceback.format_exc().splitlines()[-1])
