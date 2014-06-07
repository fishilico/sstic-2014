#!/usr/bin/env python3
"""Parse a firmware binary file"""

import os.path
import instructions


CODE_LABELS = {
    0x000: 'start',
    0x054: 'expand_key(r0=expanded_key, r1=key, r2=size)',
    0x064: '_loop1',
    0x06e: '_loop1_brk',
    0x07a: '_loop2',
    0x09c: 'decrypt(r0=expanded_key, r1=buffer, r2=size)',
    0x09e: '_fct_9c',
    0x0b2:  '_loop',
    0x0d8: 'exit',
    0x0dc: 'puts(r0=text, r1=count)',
    0x0e0: 'get_cpu_cycles(r0=buffer_for_uint16be)',
    0x0e4: 'atou16be(r0=string)',  # Read an big endian 16-bit integer
    0x0f8: 'strchr(r0=string, r1=character)',
    0x0fe: '_loop',
    0x10e: '_return0',
    0x110: '_return',
    0x112: 'itoa_hexa(r0=buffer, r1=number)',
    0x122: '_loop',
    0x130: '_is_below_10',
    0x134: '_endif',
    0x146: '_return',
    0x148: 'itoa(r0=buffer, r1=number)',
    0x158: '_loop',
}
DATA_LABELS = {
    0x17c: 'text("YeahRiscIsGood!")',
    0x18c: 'text("Firmware v1...")',
    0x1a8: 'text("Halting.")',
    0x1b2: 'encrypted_data',
}


def main():
    curdir = os.path.dirname(__file__)
    with open(os.path.join(curdir, 'fw.bin'), 'rb') as f:
        data = f.read()
    assert len(data) == 0x1dc
    instructions.dump(data, 0, 0x17c, CODE_LABELS, DATA_LABELS)


if __name__ == '__main__':
    main()
