#!/usr/bin/env python3
"""Unpack badbios.bin"""

import arm64emu
import os.path
import traceback


class BadBiosEmu(arm64emu.ARM64LinuxEmu):

    def __init__(self):
        curdir = os.path.dirname(__file__)
        disasm = os.path.join(curdir, 'badbios-400000.bin.disasm')
        super(BadBiosEmu, self).__init__(
            disasm,
            program_name='badbios.bin',
            verbosity=arm64emu.VERBOSITY_SYSCALL | arm64emu.VERBOSITY_CALL)

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
try:
    machine.run()
except Exception:
    print(traceback.format_exc().splitlines()[-1])

curdir = os.path.dirname(__file__)
machine.dump_instrdesc('badbios-instructions.out', curdir)
for addr in (0x30000000, 0x30010000, 0x30020000):
    filename = os.path.join(curdir, 'badbios-{:x}.bin'.format(addr))
    with open(filename, 'wb') as f:
        f.write(machine.mem.zones[addr])
