#!/usr/bin/env python3
"""Dump instructions from a structure"""


def dump(fw, offset, code_limit, code_labels, data_labels):
    """
    Parameters:
        fw: bytes of code and data of a firmware
        offset: where fw is mapped into memory
        code_limit: address between code (before) and data (after)
        code_labels: dict of labels for code
        data_labels: dict of labels for data
    """
    addr = offset
    while addr < code_limit:
        desc = ''
        instrlen = 2
        opcode = fw[addr - offset]
        byte2 = fw[addr - offset + 1]
        regD = opcode & 0xf
        regA = byte2 >> 4
        regB = byte2 & 0xf
        if opcode & 0xf0 == 0x20:
            assert fw[addr - offset + 2] == 0x10 + regD
            data = (byte2 << 8) | fw[addr - offset + 3]
            if data < 10:
                desc = 'r{} := {}'.format(regD, data)
            else:
                desc = 'r{} := 0x{:02x}'.format(regD, data)
            if data in data_labels:
                desc += '     \t; ' + data_labels[data]
            instrlen = 4
        elif opcode & 0xf0 == 0x30:
            if regA == regB:
                desc = 'r{} := 0'.format(regD)
            else:
                desc = 'r{} := r{} ^ r{}'.format(regD, regA, regB)
        elif opcode & 0xf0 == 0x40:
            desc = 'r{} := r{} | r{}'.format(regD, regA, regB)
        elif opcode & 0xf0 == 0x50:
            # Often 3xxx for "test x" and 3xyy for "rx = ry"
            if regA == regB == regD:
                desc = 'test r{}'.format(regD)
            elif regA == regB:
                desc = 'r{} := r{}'.format(regD, regA)
            else:
                desc = 'r{} := r{} & r{}'.format(regD, regA, regB)
        elif opcode & 0xf0 == 0x60:
            desc = 'r{} := r{} + r{}'.format(regD, regA, regB)
        elif opcode & 0xf0 == 0x70:
            desc = 'r{} := r{} - r{}'.format(regD, regA, regB)
        elif opcode & 0xf0 == 0x80:
            desc = 'r{} := r{} * r{}'.format(regD, regA, regB)
        elif opcode & 0xf0 == 0x90:
            desc = 'r{} := r{} / r{}'.format(regD, regA, regB)
        elif 0xa0 <= opcode <= 0xc7:
            # Branching
            branch = addr + 2 + byte2 + ((opcode & 3) << 8)
            if opcode & 2:
                branch -= 0x400

            if opcode & 0xfc == 0xa0:
                desc = 'if =0: jump 0x{:03x}'.format(branch)
            elif opcode & 0xfc == 0xa4:
                desc = 'if !=0: jump 0x{:03x}'.format(branch)
            elif opcode & 0xfc == 0xa8:
                desc = 'if <0: jump 0x{:03x}'.format(branch)
            elif opcode & 0xfc == 0xac:
                desc = 'if >=0: jump 0x{:03x}'.format(branch)
            elif opcode & 0xfc == 0xb0:
                desc = 'jump 0x{:03x}'.format(branch)
            elif opcode & 0xfc == 0xc0:
                desc = 'call 0x{:03x}        '.format(branch)
            else:
                desc = '??'
            if branch in code_labels:
                desc += '\t; ' + code_labels[branch]
        elif opcode == 0xc8:
            num = byte2
            desc = 'syscall {}'.format(num)
        elif opcode == 0xd0 and byte2 == 0xf:
            desc = 'ret'
        elif opcode == 0xd0 and byte2 == 0:
            desc = 'jump r0'
        elif opcode == 0xd8 and byte2 == 0:
            desc = 'sysret'
        elif opcode & 0xf0 == 0xe0:
            desc = 'r{} := *(r{}+r{})'.format(regD, regA, regB)
        elif opcode & 0xf0 == 0xf0:
            desc = '*(r{}+r{}) := r{}'.format(regA, regB, regD)
        else:
            desc = '??'

        hexdata = ''.join(
            '{:02x}'.format(b) for b in fw[addr - offset:addr - offset + instrlen])
        if addr in code_labels:
            if code_labels[addr][0] != '_':
                print('')
            print('{}:'.format(code_labels[addr]))
        print('  {:04x}: {:9s} {}'.format(addr, hexdata, desc))
        addr += instrlen
