#!/usr/bin/env python3
"""Decrypt 0x500000"""

import os.path
import re
import struct
import sys
import arm64emu


curdir = os.path.dirname(__file__)


class BadBiosEmu(arm64emu.ARM64LinuxEmu):

    def __init__(self):
        disasm = os.path.join(curdir, 'badbios-400000.bin.disasm')
        super(BadBiosEmu, self).__init__(
            disasm,
            program_name='badbios.bin',
            verbosity=arm64emu.VERBOSITY_NONE)

        for addr in (0x400000, 0x500000):
            filename = os.path.join(curdir, 'badbios-{:x}.bin'.format(addr))
            with open(filename, 'rb') as f:
                self.mem.load_mem(addr, f.read())
        self.branch(0x400514)

    def syshook_mmap(self, addr, size, prot, flags):
        if (self.regs['pc'], size) == (0x4029ac, 0x1000):
            return 0x30000000
        elif (self.regs['pc'], size) == (0x4029ec, 0x10000):
            return 0x30010000
        elif (self.regs['pc'], size) == (0x402a68, 0x1000):
            return 0x30020000
        elif (self.regs['pc'], size) == (0x401308, 0x1000):
            return 0x30030000
        elif (self.regs['pc'], size) == (0x400ea8, 0x1000):
            return 0x30040000


machine = BadBiosEmu()
# Initialize memory: run until first call to 0x4004a4
while machine.regs['pc'] != 0x4000e8:
    machine.run_instruction()

# Check expected state
assert machine.regs['x0'] == 0x30000010
assert machine.regs['x1'] == 0x30010000
assert machine.regs['x2'] == 0x30020000
assert machine.regs['x3'] == 64

data = b''
for offset in range(0, 0x10000, 0x40):
    # Erase destination buffer
    machine.mem.write_bytes(0x30020000, b'\0' * 0x40)
    # Setup key (cf. 0x4021a8)
    machine.mem.write_uint16(0x30000040, offset >> 6)
    machine.mem.write_uint16(0x30000080, 0)
    # Setup registers
    machine.regs['x0'] = 0x30000010
    machine.regs['x1'] = 0x30010000 + offset
    machine.regs['x2'] = 0x30020000
    machine.regs['x3'] = 64

    # Verify the key
    key = machine.mem[0x30000010:0x30000050]
    assert key[:0x10] == b'expand 16-byte k'
    assert key[0x10:0x18] == b'\x0b\xad\xb1\x05\x0b\xad\xb1\x05'
    assert key[0x18:0x20] == b'\x0b\xad\xb1\x05\x0b\xad\xb1\x05'
    assert key[0x20:0x28] == b'\x0b\xad\xb1\x05\x0b\xad\xb1\x05'
    assert key[0x28:0x30] == b'\x0b\xad\xb1\x05\x0b\xad\xb1\x05'
    assert struct.unpack('<H', key[0x30:0x32])[0] << 6 == offset
    assert key[0x32:0x40] == b'\0' * 14

    # Run decrypt routine
    machine.branch(0x4000e8)
    while machine.regs['pc'] < 0x400400:
        machine.run_instruction()
    # Retrieve cleartext
    data += machine.mem[0x30020000:0x30020040]

# Save result
with open('badbios-decrypt.bin', 'wb') as f:
    f.write(data)
