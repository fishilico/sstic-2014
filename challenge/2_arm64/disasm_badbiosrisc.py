#!/usr/bin/env python3
"""Dissassemble badbios-decrypt.bin"""

import os.path
import struct


def get_instr_description(instruction):
    firstbyte = instruction & 0xff
    regD = 'r' + str((instruction >> 8) & 0xf)
    regS = 'r' + str((instruction >> 12) & 0xf)
    offset = (instruction >> 16) & 0xffff

    if firstbyte == 0:
        value = (instruction << 4) & 0xffff0000
        if not value:
            return '{} = 0'.format(regD)
        return '{} = 0x{:x}'.format(regD, value)
    elif firstbyte == 1:
        value = (instruction >> 12) & 0xffff
        return '{} |= 0x{:x}'.format(regD, value)
    elif firstbyte == 2:
        if regS != 'r0':
            return '{} = *(uint32*)({} + 0x{:04x})'.format(regD, regS, offset)
        elif offset < 0x40 and not (offset & 3):
            # mov between registers
            return '{} = r{}'.format(regD, offset // 4 + 1)
        else:
            return '{} = *(uint32*)(0x{:04x})'.format(regD, offset)
    elif firstbyte == 3:
        if regS != 'r0':
            return '{} = *(uint16*)({} + 0x{:04x})'.format(regD, regS, offset)
        else:
            return '{} = *(uint16*)(0x{:04x})'.format(regD, offset)
    elif firstbyte == 4:
        if regS != 'r0':
            return '{} = *(uint8*)({} + 0x{:04x})'.format(regD, regS, offset)
        else:
            return '{} = *(uint8*)(0x{:04x})'.format(regD, offset)
    elif firstbyte == 5:
        if regS != 'r0':
            return '*(uint32*)({} + 0x{:04x}) = {}'.format(regS, offset, regD)
        else:
            return '*(uint32*)(0x{:04x}) = {}'.format(offset, regD)
    elif firstbyte == 6:
        if regS != 'r0':
            return '*(uint16*)({} + 0x{:04x}) = {}'.format(regS, offset, regD)
        else:
            return '*(uint16*)(0x{:04x}) = {}'.format(offset, regD)
    elif firstbyte == 7:
        if regS != 'r0':
            return '*(uint8*)({} + 0x{:04x}) = {}'.format(regS, offset, regD)
        else:
            return '*(uint8*)(0x{:04x}) = {}'.format(offset, regD)
    elif firstbyte == 8:
        regS = 'r' + str((instruction >> 9) & 0xf)
        cc = (instruction >> 13) & 7
        branch_desc = 'call' if instruction & 0x100 else 'branch'
        branch_desc += ' 0x{:04x}'.format(offset)
        if cc == 0:
            return branch_desc
        elif cc == 1:
            return ''
        elif cc == 2:
            return branch_desc + ' if ' + regS + ' == 0'
        elif cc == 3:
            return branch_desc + ' if ' + regS + ' != 0'
        elif cc == 4:
            return branch_desc + ' if ' + regS + ' < 0'
        elif cc == 5:
            return branch_desc + ' if ' + regS + ' > 0'
        elif cc == 6:
            return branch_desc + ' if ' + regS + ' <= 0'
        elif cc == 7:
            return branch_desc + ' if ' + regS + ' >= 0'
    elif firstbyte == 9:
        return '{0} = ~{0}'.format(regD)
    elif firstbyte == 0xa:
        if regD == regS:
            return '{} = 0'.format(regD)
        return '{} ^= {}'.format(regD, regS)
    elif firstbyte == 0xb:
        return '{} |= {}'.format(regD, regS)
    elif firstbyte == 0xc:
        return '{} &= {}'.format(regD, regS)
    elif firstbyte == 0xd:
        return '{} <<= {}'.format(regD, regS)
    elif firstbyte == 0xe:
        return '{} >>= {}'.format(regD, regS)
    elif firstbyte == 0xf:
        return '{0} = ASR({0}, {1})'.format(regD, regS)
    elif firstbyte == 0x10:
        return '{0} = ({0} << {1}) | ({0} >> (4 - ({1}&3))'.format(regD, regS)
    elif firstbyte == 0x11:
        return '{0} = ({0} >> {1}) | ({0} << (4 - ({1}&3))'.format(regD, regS)
    elif firstbyte == 0x12:
        return '{} += {}'.format(regD, regS)
    elif firstbyte == 0x13:
        return '{} -= {}'.format(regD, regS)
    elif firstbyte == 0x14:
        return '{} *= {}'.format(regD, regS)
    elif firstbyte == 0x15:
        return '{} /= {}'.format(regD, regS)
    elif firstbyte == 0x16:
        return '{} ++'.format(regD)
    elif firstbyte == 0x17:
        return '{} --'.format(regD)

    elif firstbyte == 0x1a:
        return 'return'
    elif firstbyte == 0x1b:
        return ''
    elif firstbyte == 0x1c:
        return 'exit(0)'
    elif firstbyte == 0x1d:
        return 'r1 = syscall(r1)'
    elif firstbyte == 0x1e:
        return '{} = bitparity({})'.format(regD, regS)
    return 'UNIMPLEMENTED INSTUCTION'


curdir = os.path.dirname(__file__)
progname = os.path.join(curdir, 'badbios-decrypt.bin')
with open(progname, 'rb') as f:
    program = f.read()

# Start after registers and stop before strings
addr = 0x40
while addr < 0x0326:
    firstbyte = program[addr]
    if firstbyte >= 32:
        break
    instrsize = 2 if firstbyte > 8 else 4
    if instrsize == 2:
        instruction = struct.unpack('<H', program[addr:addr+2])[0]
    else:
        instruction = struct.unpack('<I', program[addr:addr+4])[0]
    assert firstbyte == instruction & 0xff

    # Merge instructions 00 and 01
    hexainstr = ('{:0' + str(2 * instrsize) + 'x}').format(instruction)
    if firstbyte == 0 and program[addr + 4] == 1 and \
            program[addr + 5] & 0xf == (instruction >> 8) & 0xf:
        value = (instruction << 4) & 0xffff0000
        value |= program[addr + 5] >> 4 & 0xf
        value |= (program[addr + 6] << 4) & 0xff0
        value |= (program[addr + 7] << 12) & 0xf000
        hexainstr += ' {:08x}'.format(
            struct.unpack('<I', program[addr+4:addr+8])[0])
        instrsize = 8
        if value < 10:
            desc = 'r{} = {}'.format((instruction >> 8) & 0xf, value)
        else:
            desc = 'r{} = 0x{:x}'.format((instruction >> 8) & 0xf, value)
    else:
        desc = get_instr_description(instruction)
    print("  {:04x}: {:>17s}  {}".format(addr, hexainstr, desc))
    addr = addr + instrsize
