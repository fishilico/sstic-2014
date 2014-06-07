#!/usr/bin/env python
"""Parse the kernel of the microcontroler unit"""

import os.path
import instructions


CODE_LABELS = {
    0xfd00: 'syscall(r0)',
    0xfd1e: '_print_err_undef_syscall',
    0xfd28: 'syscall1_halt',
    0xfd36: 'syscall2_puts',
    0xfd4a: 'syscall3_get_cpu_cycles',
    0xfd70: 'syscall0_sysreset',
    0xfdb0: 'read_uint16be(r0=buffer, r1=num)',
    0xfdc4: 'write_uint16be(r0=buffer, r1=num)',
    0xfdd6: 'memset(addr=r0, char=r1, size=r2)',
    0xfde6: 'puts(buf=r0, len=r1)',
    0xfdfa: '_putc',
    0xfe0c: '_fe0c',
    0xfe18: '_return',
    0xfe1a: '_print_err_unallowedaddr',
}
DATA_LABELS = {
    # [F000-FBFF] - Secret memory area
    0xf000: 'syscall_table',

    # [FC00-FCFF] - HW Registers
    0xfc00: 'hwreg_outputbyte',
    0xfc10: 'hwreg_halt',
    0xfc12: 'hwreg_cpucycles',
    0xfc20: 'hwreg_user_r0',
    0xfc22: 'hwreg_user_r1',
    0xfc3a: 'hwreg_user_r13',

    # [FD00-FFFF] - ROM (kernel)
    0xfd28: '@syscall1_halt',
    0xfd36: '@syscall2_puts',
    0xfd4a: '@syscall3_get_cpu_cycles',
    0xfe26: 'text("[ERROR] Printing at unallo...")',
    0xfe5a: 'text("[ERROR] Undefined system call...")',
    0xfe86: 'text("System reset.")',
}


def main():
    curdir = os.path.dirname(__file__)
    with open(os.path.join(curdir, 'kernel.bin'), 'rb') as f:
        data = f.read()
    assert len(data) == 0x1a0
    instructions.dump(data, 0xfd00, 0xfe26, CODE_LABELS, DATA_LABELS)


if __name__ == '__main__':
    main()
