#!/usr/bin/env python3
"""Emulate an ARM64 processor"""
import os.path
import re
import sys

from load_objdump import load_objdump_d
import memory_map


# Strack addresses begin with "574" like "STA"
STACK_LIMIT = 0x57400000
STACK_BASE = 0x574f0000

# Verbosity of the printed messages
VERBOSITY_READ = 0x01
VERBOSITY_LOAD = 0x02
VERBOSITY_CONDBRANCH = 0x04
VERBOSITY_INSTR = 0x08
VERBOSITY_BRANCH = 0x10
VERBOSITY_CALL = 0x20
VERBOSITY_SYSCALL = 0x40

VERBOSITY_NONE = 0
VERBOSITY_ALL = 0x7f

# Log at most 3 executions per instruction
MAX_LOG_BY_INSTR = 3

# Magic number to say "size of 4 or 8 bytes"
SZ_48 = -48

# Some masks to prevent typos
UINT32_MASK = (1 << 32) - 1
UINT64_MASK = (1 << 64) - 1


# Some exceptions to suspend the execution
class NormalExit(Exception):

    def __init__(self, status):
        self.status = status


class OutPC(Exception):
    """The program counter is going out of the loaded instructions"""

    def __init__(self, pc):
        self.pc = pc


class MmapNeeded(Exception):
    """mmap needs to be overloaded"""

    def __init__(self, addr, size, prot, flags, pc):
        self.addr = addr
        self.size = size
        self.prot = prot
        self.flags = flags
        self.pc = pc

    def __str__(self):
        return "return value not defined for mmap({}, {}, {}, {}) at 0x{:x}." \
            .format(self.addr, self.size, self.prot, self.flags, self.pc)


# Helper functions
def sxtw(word):
    """Sign-extend word to double word"""
    assert 0 <= word <= UINT32_MASK
    if word & (1 << 32):
        word += UINT32_MASK << 32
    return word


def ror(value, shift, size):
    """Rotate right"""
    low_val = value & ((1 << shift) - 1)
    return (value >> shift) + (low_val << (8 * size - shift))


def ubfx(value, lsb, width):
    """Unsigned Bitfield Extract"""
    return (value >> lsb) & ((1 << width) - 1)


def sbfiz(value, lsb, width, size):
    """Signed Bitfield Insert in Zero"""
    if value & (1 << (width - 1)):
        # Extend sign
        sign_ext = (1 << (8 * size)) - (1 << (lsb + width))
        return ((value & ((1 << width) - 1)) << lsb) | sign_ext
    else:
        return (value & ((1 << width) - 1)) << lsb


class ARM64LinuxEmu(object):
    """Emulate a Linux ARM64 machine"""

    def __init__(self, disasm_file, program_name='a.out', verbosity=0):
        # Set verbosity
        self.verb = verbosity

        # Initialize registers
        self.regs = {}
        for i in range(31):
            self.regs['x' + str(i)] = 0
        # PC needs to be set up with a call to "branch()"
        self.regs['pc'] = None
        self.regs['sp'] = 0
        self.flags = dict((f, False) for f in 'NZCV')

        # Some instructions like "stp x29, x30, [sp,#-16]!" might update sp
        # before reading every value. Store the new value in temp_regs
        self.temp_regs = None

        self.mem = memory_map.MemMap()
        self.mem.add_mem(STACK_LIMIT, STACK_BASE - STACK_LIMIT)

        # Push environment and program arguments
        env = [b'PATH=/bin:/sbin']
        args = [program_name.encode('utf8')]
        rev_env = []
        rev_argv = []
        sp = STACK_BASE
        for e in env[::-1]:
            sp -= 8 * (len(e) // 8 + 1)  # ceil((len(a)+1)/8) = len(a)//8 + 1
            self.mem.write_bytes(sp, e)
            rev_env.append(sp)
        for a in args[::-1]:
            sp -= 8 * (len(a) // 8 + 1)  # ceil((len(a)+1)/8) = len(a)//8 + 1
            self.mem.write_bytes(sp, a)
            rev_argv.append(sp)
        # Push NULL, envp vector, NULL, argv vector, argc
        sp -= 8
        self.mem.write_uint64(sp, 0)
        for ptr in rev_env:
            sp -= 8
            self.mem.write_uint64(sp, ptr)
        sp -= 8
        self.mem.write_uint64(sp, 0)
        for ptr in rev_argv:
            sp -= 8
            self.mem.write_uint64(sp, ptr)
        sp -= 8
        self.mem.write_uint64(sp, len(args))
        self.regs['sp'] = sp

        self.instructions, self.base_instr = load_objdump_d(disasm_file)
        self.instrdesc = [None] * len(self.instructions)

        # Call indentation
        self.call_level = 0

    def log(self, mne, description):
        """Save a description of the current instruction"""
        instr = self.instructions[self.instr_index]

        # Log instruction into internal table
        if mne == instr[0]:
            if self.instrdesc[self.instr_index] is None:
                self.instrdesc[self.instr_index] = [description]
            elif len(self.instrdesc[self.instr_index]) < MAX_LOG_BY_INSTR:
                self.instrdesc[self.instr_index].append(description)

        # Print something
        text_instr = mne
        if mne == instr[0] or mne == '!':
            if not (self.verb & VERBOSITY_INSTR):
                return
            if instr[1]:
                text_instr += ' ' + ', '.join(instr[1])
        elif instr[0] == 'svc' and mne.startswith('syscall'):
            if not (self.verb & VERBOSITY_SYSCALL):
                return
        print('<{:05x}: {:30s}> {}'.format(self.regs['pc'], text_instr, description))

    def debug(self, message):
        """Print a debug message"""
        print('\033[37m{}\033[m'.format(message))

    def flags_state(self):
        """Describe the state of the flags"""
        return ''.join(f if self.flags[f] else f.lower() for f in 'NZCV')

    def _inc_pc(self):
        self.regs['pc'] += 4
        self.instr_index += 1

    def branch(self, new_pc, cond_result=True):
        """Branch to address if cond_result is True,
        to the next instruction overwise
        """
        if not cond_result:
            if self.verb & VERBOSITY_BRANCH:
                self.debug('\033[31mNoBranch 0x{:x}'.format(new_pc))
            return self._inc_pc()
        if self.verb & VERBOSITY_BRANCH:
            self.debug('\033[36mBranch 0x{:x}'.format(new_pc))

        index = (new_pc - self.base_instr) // 4
        assert index * 4 + self.base_instr == new_pc
        if not 0 <= index <= len(self.instructions):
            raise OutPC(new_pc)
        self.instr_index = index
        self.regs['pc'] = new_pc

    @staticmethod
    def get_regsize(reg):
        """Get the size of a register"""
        if reg[0] == 'x' or reg == 'sp':
            return 8
        elif reg[0] == 'w':
            return 4
        else:
            raise Exception("Unknow size of reg {}".format(reg))

    def get_value(self, asmval, size):
        """Get the value of an assembly string"""
        if asmval in ('wzr', 'xzr'):
            # Zero register
            if asmval == 'wzr' and size in (4, SZ_48):
                return 0
            if asmval == 'xzr' and size in (8, SZ_48):
                return 0
            raise Exception(
                "Unknwon use of {} with size {}".format(asmval, size))
        elif asmval.startswith('#0x'):
            value = int(asmval[3:], 16)
            if size != SZ_48 and value >= (1 << (size * 8)):
                raise Exception(
                    "Too big value for instruction size (expected {})"
                    .format(size))
            return value
        elif asmval in self.regs and size in (8, SZ_48):
            value = self.regs[asmval]
            if self.verb & VERBOSITY_READ:
                self.debug('Read {} = 0x{:x}'.format(asmval, value))
            return value
        elif asmval[0] == 'w' and size in (1, 2, 4, SZ_48):
            xreg = 'x' + asmval[1:]
            if xreg in self.regs:
                value = self.regs[xreg] & 0xffffffff
                # Reduce value size if needed
                if size == 1:
                    value &= 0xff
                elif size == 2:
                    value &= 0xffff
                if self.verb & VERBOSITY_READ:
                    self.debug('Read {} = 0x{:x}'.format(asmval, value))
                return value
        elif asmval[0] == '[':
            assert size != SZ_48
            addr = self.get_addr(asmval)
            value = self.mem.get_uint(addr, size)
            if self.verb & VERBOSITY_LOAD:
                self.debug('Load *{:x} = 0x{:x}'.format(addr, value))
            return value
        raise Exception(
            "Not yet implemented value format for {}, size {}"
            .format(asmval, size))

    # PreIndex address notation
    RE_ADDR_PREINDEX = re.compile(r'^\[([^,]+),#([-0-9]+)\]!$')
    # PostIndex address notation
    RE_ADDR_POSTINDEX = re.compile(r'^\[([^,]+)\],#([-0-9]+)$')
    # Base + offset notation
    RE_ADDR_OFFSET = re.compile(r'^\[([^,]+),#([-0-9]+)\]$')
    # Base + reg << imm (Logical Shift Left)
    RE_ADDR_REGLSL = re.compile(r'^\[([^,]+),([^,]+),lsl #([-0-9]+)\]$')

    def get_addr(self, asmval):
        """Get an address from an assembly string"""
        if asmval.startswith('0x'):
            return int(asmval[2:], 16)

        matches = self.RE_ADDR_PREINDEX.match(asmval)
        if matches is not None:
            reg, offset = matches.groups()
            addr = self.get_value(reg, 8) + int(offset)
            self.temp_regs[reg] = addr
            return addr

        matches = self.RE_ADDR_POSTINDEX.match(asmval)
        if matches is not None:
            reg, offset = matches.groups()
            addr = self.get_value(reg, 8)
            self.temp_regs[reg] = addr + int(offset)
            return addr

        matches = self.RE_ADDR_OFFSET.match(asmval)
        if matches is not None:
            reg, offset = matches.groups()
            return self.get_value(reg, 8) + int(offset)

        matches = self.RE_ADDR_REGLSL.match(asmval)
        if matches is not None:
            regbase, regshifted, shift = matches.groups()
            offset = self.get_value(regshifted, 8) << int(shift)
            return self.get_value(regbase, 8) + offset

        if asmval[0] == '[' and asmval[-1] == ']':
            if ',' in asmval:
                # e.g. "[x4,x17]"
                return sum(self.get_value(v, 8)
                           for v in asmval[1:-1].split(','))
            else:
                # e.g. "[x0]"
                return self.get_value(asmval[1:-1], 8)
        raise Exception(
            "Not yet implemented addr format for {}".format(asmval))

    def get_shiftval(self, asmval):
        """Helper to convert a value used in a shift to an integer"""
        if asmval[0] == '#':  # e.g. '#42"
            return int(asmval[1:])
        elif asmval[0] in ('w', 'x'):
            return self.get_value(asmval, SZ_48)
        raise Exception("Unknown shift format {}".format(asmval))

    def store_reg(self, reg, value, size):
        """Store a value in a register"""
        if size == 8 or (size == SZ_48 and self.get_regsize(reg) == 8):
            if reg in self.regs:
                self.regs[reg] = value & UINT64_MASK
            else:
                raise Exception(
                    "Unknown destination 64-bits reg {}".format(reg))
        elif size == 4 or (size == SZ_48 and self.get_regsize(reg) == 4):
            if reg[0] == 'w':
                xreg = 'x' + reg[1:]
                if xreg in self.regs:
                    self.regs[xreg] = value & UINT32_MASK
                else:
                    raise Exception(
                        "Unknown destination 32-bits reg {}".format(reg))
        else:
            raise Exception(
                "Unable to guess the size of reg {}".format(reg))

    def get_cond(self, cc):
        """Evaluation the condition according to the flags"""
        if cc == 'eq':  # Equal
            return self.flags['Z']
        elif cc == 'ne':  # Not equal
            return not self.flags['Z']
        elif cc == 'cs':  # Carry set = Unsigned higher or same
            return self.flags['C']
        elif cc == 'cc':  # Carry clear = Unsigned lower
            return not self.flags['C']
        elif cc == 'mi':  # Minus (negative)
            return self.flags['N']
        elif cc == 'pl':  # Plus (positive or zero)
            return not self.flags['N']
        elif cc == 'hi':  # Unsigned higher
            return self.flags['C'] and not self.flags['Z']
        elif cc == 'ls':  # Unsigned lower or same
            return not self.flags['C'] or self.flags['Z']
        elif cc == 'ge':  # Signed greater than or equal
            return self.flags['N'] == self.flags['V']
        elif cc == 'lt':  # Signed less than
            return self.flags['N'] != self.flags['V']
        elif cc == 'gt':  # Signed greater than
            return not self.flags['Z'] and \
                self.flags['N'] == self.flags['V']
        elif cc == 'le':  # Signed less than or equal
            return self.flags['Z'] or self.flags['N'] != self.flags['V']
        elif cc == 'al':  # Always
            return True
        else:
            raise Exception("Unsupported conditional branch instruction")

    def set_cond_add(self, value1, value2, size):
        """Set condition flags after ADDS and CNP"""
        # documentation: http://infocenter.arm.com/help/index.jsp?topic=
        #/com.arm.doc.dui0553a/BABEHFEF.html
        bitsize = 8 * size
        bitmask = (1 << bitsize) - 1
        signmask = (1 << (bitsize - 1))
        sumval = (value1 & bitmask) + (value2 & bitmask)
        sign1 = value1 & signmask
        sign2 = value2 & signmask
        signd = sumval & signmask
        self.flags['N'] = (signd != 0)
        self.flags['Z'] = (sumval & bitmask == 0)
        self.flags['C'] = (sumval & (1 << bitsize) != 0)
        # signed overflow: (+) + (+) = (-) or (-) + (-) = (+)
        self.flags['V'] = (sign1 == sign2 != signd)

    def set_cond_sub(self, value1, value2, size):
        """Set condition flags after SUBS and CMP"""
        bitsize = 8 * size
        bitmask = (1 << bitsize) - 1
        signmask = (1 << (bitsize - 1))
        # Read http://en.wikipedia.org/wiki/Carry_flag to understand why the
        # substraction is done like this
        diff = (value1 & bitmask) + ((~value2) & bitmask) + 1
        sign1 = value1 & signmask
        sign2 = value2 & signmask
        signd = diff & signmask
        self.flags['N'] = (signd != 0)
        self.flags['Z'] = (diff & bitmask == 0)
        self.flags['C'] = (diff & (1 << bitsize) != 0)
        self.flags['V'] = (sign1 != sign2 == signd)

    def run(self):
        """Run the program until an exception occurs"""
        while True:
            pc = self.regs['pc']
            instr = self.instructions[self.instr_index]
            try:
                self.run_instruction(instr)
            except NormalExit:
                raise
            except OutPC:
                raise
            except MmapNeeded:
                raise
            except Exception:
                sys.stderr.write(
                    "Exception while running @{:x} {}\n".format(pc, instr))
                raise

    def run_instruction(self, instr=None):
        """Run a single instruction"""
        if instr is None:
            instr = self.instructions[self.instr_index]
        assert self.temp_regs is None
        self.temp_regs = {}
        self._run_instruction_internal(instr)
        for reg, value in self.temp_regs.items():
            self.log('!', '{} := 0x{:x}'.format(reg, value))
            self.regs[reg] = value
        self.temp_regs = None

    def _run_instruction_internal(self, instr):
        mne, params = instr
        if (mne == 'mov' or mne.startswith('ldr')) and len(params) == 2:
            size = 8
            if mne == 'ldrb':
                size = 1
            elif mne == 'ldrh':
                size = 2
            elif mne in ('ldrw', 'ldrsw'):
                size = 4
            elif mne in ('mov', 'ldr'):
                size = self.get_regsize(params[0])
            elif mne not in ('mov', 'ldr'):
                raise Exception(
                    "Unimplemented mov or ldr instruction: {}".format(mne))
            value = self.get_value(params[1], size)
            if size < 8 and 's' in mne[-2:]:
                # Sign-extend value
                if value & (1 << (size - 1)):
                    value += (1 << 64) - (1 << size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, SZ_48)
            return self._inc_pc()

        elif mne == 'ldp' and len(params) == 3:
            addr = self.get_addr(params[2])
            value1 = self.mem.get_uint(addr, 8)
            value2 = self.mem.get_uint(addr + 8, 8)
            if self.verb & VERBOSITY_LOAD:
                self.debug('Load pair *{:x} = 0x{:x}, 0x{:x}'
                           .format(addr, value1, value2))
            self.log(mne, '{}, {} := 0x{:x}, 0x{:x}'
                     .format(params[0], params[1], value1, value2))
            self.store_reg(params[0], value1, SZ_48)  # TODO: check order
            self.store_reg(params[1], value2, SZ_48)
            return self._inc_pc()

        elif mne.startswith('str') and len(params) == 2:
            size = 8
            if mne == 'strb':
                size = 1
            elif mne == 'strh':
                size = 2
            elif mne == 'strw':
                size = 4
            elif mne == 'str':
                size = self.get_regsize(params[0])
            elif mne != 'str':
                raise Exception(
                    "Unimplemented str instruction: {}".format(mne))
            value = self.get_value(params[0], size)
            addr = self.get_addr(params[1])
            self.log(mne, '*0x{:x} := 0x{:x}'.format(addr, value))
            self.mem.write_uint(addr, value, size)
            return self._inc_pc()

        elif mne == 'stp' and len(params) == 3:
            value1 = self.get_value(params[0], 8)
            value2 = self.get_value(params[1], 8)
            addr = self.get_addr(params[2])
            self.log(mne, '*0x{:x} := 0x{:x}, 0x{:x}'.format(addr, value1, value2))
            self.mem.write_uint64(addr, value1)  # TODO: check order
            self.mem.write_uint64(addr + 8, value2)
            return self._inc_pc()

        elif mne == 'sxtw' and len(params) == 2:
            # Sign Extend
            value = self.get_value(params[1], 4)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, 8)
            return self._inc_pc()

        elif mne == 'uxtb' and len(params) == 2:
            value = self.get_value(params[1], 1)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, SZ_48)
            return self._inc_pc()

        elif mne == 'movk' and len(params) == 3:
            # Move imm16 with keep
            value = self.get_value(params[1], 2)
            mask = 0xffff
            if params[2].startswith('lsl #'):
                shift = int(params[2][len('lsl #'):])
                value = value << shift
                mask = mask << shift
            value |= self.get_value(params[0], SZ_48) & ~mask
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, SZ_48)
            return self._inc_pc()

        elif mne in ('adr', 'adrp') and len(params) == 2:
            addr = self.get_addr(params[1])
            self.log(mne, '{} := 0x{:x}'.format(params[0], addr))
            self.store_reg(params[0], addr, 8)
            return self._inc_pc()

        elif mne == 'add' and len(params) == 3:
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            value += self.get_value(params[2], size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'add' and len(params) == 4:
            size = self.get_regsize(params[0])
            if params[3] == 'sxtw':
                value = sxtw(self.get_value(params[2], 4))
                value += self.get_value(params[1], 8)
                size = 8  # Force params[0] to be an extended register
            elif params[3] == 'uxtb':
                value = self.get_value(params[2], 1)
                if not 0 <= value <= 0xff:
                    raise Exception(
                        "Undefined behavior: uxtb used on something larger than a byte")
                value += self.get_value(params[1], 8)
                size = 8
            elif params[3] == 'uxtw':
                value = self.get_value(params[2], 4)
                value += self.get_value(params[1], 8)
                size = 8
            elif params[3].startswith('lsl #'):
                shift = int(params[3][len('lsl #'):])
                value = (self.get_value(params[2], 8) << shift)
                value += self.get_value(params[1], 8)
                size = 8
            else:
                raise Exception("Unimplemented size modifier")
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'cmn' and len(params) == 2:
            # Compare with negative
            size = self.get_regsize(params[0])
            value1 = self.get_value(params[0], size)
            value2 = self.get_value(params[1], size)
            self.set_cond_add(value1, value2, size)
            self.log(mne, 'flags := {}'.format(self.flags_state()))
            return self._inc_pc()
        elif mne == 'adds' and len(params) == 3:
            size = self.get_regsize(params[0])
            value1 = self.get_value(params[1], size)
            value2 = self.get_value(params[2], size)
            self.set_cond_add(value1, value2, size)
            value = value1 + value2
            self.log(mne, '{} := 0x{:x}, flags := {}'
                     .format(params[0], value, self.flags_state()))
            self.store_reg(params[0], value, size)
            return self._inc_pc()
        elif mne == 'adds' and len(params) == 4:
            size = self.get_regsize(params[0])
            value1 = self.get_value(params[1], size)
            value2 = self.get_value(params[2], size)
            if params[3].startswith('lsl #'):
                value2 = value2 << int(params[3][len('lsl #'):])
            else:
                raise Exception(
                    "Unimplemented last param: {}".format(param[3]))
            self.set_cond_add(value1, value2, size)
            value = value1 + value2
            self.log(mne, '{} := 0x{:x}, flags := {}'
                     .format(params[0], value, self.flags_state()))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'sub' and len(params) == 3:
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            value -= self.get_value(params[2], size)
            value &= (1 << 64) - 1
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'cmp' and len(params) == 2:
            size = self.get_regsize(params[0])
            value1 = self.get_value(params[0], size)
            value2 = self.get_value(params[1], size)
            self.set_cond_sub(value1, value2, size)
            self.log(mne, 'flags := {}'.format(self.flags_state()))
            return self._inc_pc()
        elif mne == 'subs' and len(params) == 3:
            size = self.get_regsize(params[0])
            value1 = self.get_value(params[1], size)
            value2 = self.get_value(params[2], size)
            self.set_cond_sub(value1, value2, size)
            value = value1 - value2
            self.log(mne, '{} := 0x{:x}, flags := {}'
                     .format(params[0], value, self.flags_state()))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'and' and len(params) == 3:
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            value &= self.get_value(params[2], size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()
        elif mne == 'and' and len(params) == 4:
            size = self.get_regsize(params[0])
            value = self.get_value(params[2], size)
            if params[3].startswith('lsr #'):
                value = value >> int(params[3][len('lsr #'):])
            else:
                raise Exception(
                    "Unimplemented last param: {}".format(param[3]))
            value &= self.get_value(params[1], size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'orr' and len(params) == 3:
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            value |= self.get_value(params[2], size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'eor' and len(params) == 3:
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            value ^= self.get_value(params[2], size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()
        elif mne == 'eor' and len(params) == 4:
            size = self.get_regsize(params[0])
            value = self.get_value(params[2], size)
            if params[3].startswith('lsr #'):
                value = value >> int(params[3][len('lsr #'):])
            else:
                raise Exception(
                    "Unimplemented last param: {}".format(param[3]))
            value ^= self.get_value(params[1], size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'mvn' and len(params) == 2:
            # Move not
            size = self.get_regsize(params[0])
            value = ~self.get_value(params[1], size)
            value &= (1 << (8 * size)) - 1
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'bic' and len(params) == 3:
            # Bit clear. "bic Xd, Xd, xzr" is a no-op
            if params[0] == params[1] and params[2] == 'xzr':
                return self._inc_pc()
            # Not implemented if not a no-op

        elif mne == 'asr' and len(params) == 3:
            # Arithmetic Shift Right
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            shift = self.get_shiftval(params[2])
            if value & (1 << (8 * size - 1)):
                # Extend sign
                sign_ext = (1 << (8 * size)) - (1 << (8 * size - shift))
                value = (value >> shift) | sign_ext
            else:
                value = (value >> shift)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, SZ_48)
            return self._inc_pc()

        elif mne == 'lsl' and len(params) == 3:
            # Logical Shift Left
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            value = value << self.get_shiftval(params[2])
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'lsr' and len(params) == 3:
            # Logical Shift Right
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            value = value >> self.get_shiftval(params[2])
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'ror' and len(params) == 3:
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            shift = self.get_shiftval(params[2])
            value = ror(value, shift, size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'madd' and len(params) == 4:
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            value *= self.get_value(params[2], size)
            value += self.get_value(params[3], size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()
        elif mne == 'mul' and len(params) == 3:
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            value *= self.get_value(params[2], size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'ubfx' and len(params) == 4:
            # Unsigned Bitfield Extract
            if params[2][0] != '#' or params[3][0] != '#':
                raise Exception("Unknown param format for UBFX")
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            lsb = int(params[2][1:])
            width = int(params[3][1:])
            value = ubfx(value, lsb, width)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'sbfiz' and len(params) == 4:
            # Signed Bitfield Insert in Zero
            # ARM doc says:
            #    SBFM Xd,Xn,r=#((64-lsb)&63),s=#(width-1), s < r
            #    Xd<64+s-r,64-r> = Xn<s:0>
            # -> hence Xd<lsb+w-1,lsb> = Xn<w-1:0>
            if params[2][0] != '#' or params[3][0] != '#':
                raise Exception("Unknown param format for SBFIZ")
            # Get the sign with one register, but I haven't understood which.
            # So only support the instruction only when Rd = Rn
            if params[0] != params[1]:
                raise Exception("SBFIZ not implemented when Rd != Rn")
            size = self.get_regsize(params[0])
            value = self.get_value(params[1], size)
            lsb = int(params[2][1:])
            width = int(params[3][1:])
            value = sbfiz(value, lsb, width, size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'clz' and len(params) == 2:
            # Count leading zeros
            size = self.get_regsize(params[1])
            value = self.get_value(params[1], size)
            value = 8 * size - value.bit_length()
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, SZ_48)
            return self._inc_pc()

        elif mne in ('b', 'bl') and len(params) == 1:
            addr = self.get_addr(params[0])
            if mne == 'bl':
                # Save pc in lr (=x30)
                self.regs['x30'] = self.regs['pc'] + 4
                if self.verb & VERBOSITY_CALL:
                    self.debug("{}Call 0x{:x}({}) from 0x{:x}".format(
                        '  ' * self.call_level,
                        addr,
                        ', '.join('{}=0x{:x}'.format(r, self.regs[r])
                                  for r in ('x0', 'x1', 'x2', 'x3', 'x4')),
                        self.regs['pc']))
                self.call_level += 1
            return self.branch(addr)

        elif mne in ('br', 'blr') and len(params) == 1:
            addr = self.get_value(params[0], 8)
            if mne == 'blr':
                self.regs['x30'] = self.regs['pc'] + 4
                if self.verb & VERBOSITY_CALL:
                    self.debug("{}Call 0x{:x}({}) from 0x{:x}".format(
                        '  ' * self.call_level,
                        addr,
                        ', '.join('{}=0x{:x}'.format(r, self.regs[r])
                                  for r in ('x0', 'x1', 'x2', 'x3', 'x4')),
                        self.regs['pc']))
                self.call_level += 1
            elif params[0] == 'x30':
                if self.verb & VERBOSITY_CALL:
                    self.debug("{}Ret 0x{:x} (x0=0x{:x}) from 0x{:x}".format(
                        '  ' * self.call_level,
                        addr, self.regs['x0'], self.regs['pc']))
                self.call_level -= 1
            return self.branch(addr)

        elif mne == 'ret' and not params:
            if self.verb & VERBOSITY_CALL:
                self.debug("{}Ret 0x{:x} (x0=0x{:x}) from 0x{:x}".format(
                    '  ' * self.call_level,
                    self.regs['x30'], self.regs['x0'], self.regs['pc']))
            self.call_level -= 1
            return self.branch(self.regs['x30'])

        elif mne.startswith('b.') and len(params) == 1:
            cond = self.get_cond(mne[2:])
            if self.verb & VERBOSITY_CONDBRANCH:
                self.debug(
                    "\033[33;1mConditional branch: {} with {} = {}"
                    .format(mne, self.flags_state(), cond))
            return self.branch(self.get_addr(params[0]), cond)

        elif mne == 'cset' and len(params) == 2:
            cond = self.get_cond(params[1])
            value = 1 if cond else 0
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, SZ_48)
            return self._inc_pc()

        elif mne == 'csel' and len(params) == 4:
            size = self.get_regsize(params[0])
            cond = self.get_cond(params[3])
            value = self.get_value(params[1 if cond else 2], size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'csneg' and len(params) == 4:
            size = self.get_regsize(params[0])
            cond = self.get_cond(params[3])
            if cond:
                value = self.get_value(params[1], size)
            else:
                value = -self.get_value(params[2], size)
            self.log(mne, '{} := 0x{:x}'.format(params[0], value))
            self.store_reg(params[0], value, size)
            return self._inc_pc()

        elif mne == 'cbz' and len(params) == 2:
            value = self.get_value(params[0], SZ_48)
            return self.branch(self.get_addr(params[1]), not value)

        elif mne == 'cbnz' and len(params) == 2:
            value = self.get_value(params[0], SZ_48)
            return self.branch(self.get_addr(params[1]), value)

        elif mne == 'tbz' and len(params) == 3:
            if params[1][0] != '#':
                raise Exception("Unknown param format for TBZ")
            value = self.get_value(params[0], SZ_48)
            bitnum = int(params[1][1:])
            return self.branch(self.get_addr(params[2]),
                               not (value & (1 << bitnum)))

        elif mne == 'tbnz' and len(params) == 3:
            if params[1][0] != '#':
                raise Exception("Unknown param format for TBNZ")
            value = self.get_value(params[0], SZ_48)
            bitnum = int(params[1][1:])
            return self.branch(self.get_addr(params[2]),
                               value & (1 << bitnum))

        elif mne == 'svc' and len(params) == 1:
            if self.get_value(params[0], SZ_48) == 0:
                self.do_syscall()
                return self._inc_pc()

        elif mne == 'nop' and params is None:
            return self._inc_pc()

        raise Exception("Unknwon mnemonic or unsupported parameter count")

    def syshook_read(self, fd, count):
        """Syscall read, returns at most count bytes"""
        return b''

    def syshook_write(self, fd, data):
        """Syscall write, returns the number of bytes written"""
        if fd not in (1, 2):
            raise Exception(
                "write doesn't support fd other than stdout and stderr")
        return len(data)

    def syshook_mmap(self, addr, size, prot, flags):
        return

    def do_syscall(self):
        """Emulate a syscall (svc #0)

        Linux syscall list: /usr/src/linux/include/uapi/asm-generic/unistd.h
        """
        index = self.regs['x8']
        args = [self.regs['x' + str(i)] for i in range(6)]
        if index == 63:
            # __NR_read(fd, buf, count)
            fd, buf, count = args[:3]
            value = self.syshook_read(fd, count)
            self.mem.write_bytes(buf, value)
            if self.verb & VERBOSITY_SYSCALL:
                print('syscall:read(fd={}, buf=0x{:x}, len={}): {}'.format(
                    fd, buf, count,
                    repr(value.decode('utf8', errors='ignore'))))
            self.regs['x0'] = len(value)
        elif index == 64:
            # __NR_write(fd, buf, count)
            fd, buf, count = args[:3]
            data = bytes(self.mem[buf:buf + count])
            if self.verb & VERBOSITY_SYSCALL:
                print('syscall:write(fd={}, buf=0x{:x}, len={}): {}'.format(
                    fd, buf, count,
                    repr(data.decode('utf8', errors='ignore'))))
            count = self.syshook_write(fd, data)
            # Return count
            self.regs['x0'] = count
        elif index == 94:
            # __NR_exit_group(status)
            status = args[0]
            if status >= 1 << 31:
                status -= 1 << 32
            if self.verb & VERBOSITY_SYSCALL:
                print('syscall:exit({})'.format(status))
            raise NormalExit(status)
        elif index == 215:
            # __NR_munmap(addr, length)
            addr, size = args[:2]
            if self.verb & VERBOSITY_SYSCALL:
                print('syscall:munmap(addr=0x{:x}, size={})'
                      .format(addr, size))
            self.mem.del_mem(addr)
            self.regs['x0'] = 0
        elif index == 222:
            # __NR3264_mmap(addr, len, prot, flags, fd, offset)
            addr, size, prot, flags, fd, offset = args
            prot_desc = []
            if prot & 1:
                prot_desc.append('PROT_READ')
            if prot & 2:
                prot_desc.append('PROT_WRITE')
            if prot & 4:
                prot_desc.append('PROT_EXEC')
            flags_desc = []
            if flags & 1:
                flags_desc.append('MAP_SHARED')
            if flags & 2:
                flags_desc.append('MAP_PRIVATE')
            if flags & 0x10:
                flags_desc.append('MAP_FIXED')
            if flags & 0x20:
                flags_desc.append('MAP_ANONYMOUS')
            description = \
                '(addr=0x{:x}, size={}, prot={}, flags={}'.format(
                    addr, size,
                    '|'.join(prot_desc) if prot else '0',
                    '|'.join(flags_desc) if flags else '0')
            if not flags & 0x20:
                description += ', fd={}, off={}'.format(fd, offset)
            description += ')'
            if self.verb & VERBOSITY_SYSCALL:
                print('syscall:mmap' + description)
            if not flags & 0x20:
                raise Exception("Unsupport non-anonymous MMap")

            # If non-fixed memory, find a good location
            if not (flags & 0x10) and not addr:
                newaddr = self.syshook_mmap(addr, size, prot, flags)
                if not newaddr:
                    # syshook_mmap hasn't found anything
                    raise MmapNeeded(addr, size, prot, flags, self.regs['pc'])
                addr = newaddr
                if self.verb & VERBOSITY_SYSCALL:
                    print('syscall:mmap ... = 0x{:x}'.format(addr))

            # Add memory and returns it
            self.mem.add_mem(addr, size)
            self.regs['x0'] = addr
        elif index == 226:
            # __NR_mprotect(addr, len, prot)
            addr, size, prot = args[:3]
            prot_desc = []
            if prot & 1:
                prot_desc.append('PROT_READ')
            if prot & 2:
                prot_desc.append('PROT_WRITE')
            if prot & 4:
                prot_desc.append('PROT_EXEC')
            if self.verb & VERBOSITY_SYSCALL:
                print(
                    'syscall:mprotect(addr=0x{:x}, size={}, prot={})'
                    .format(
                        addr, size,
                        '|'.join(prot_desc) if prot else '0'))
            # Check that the page exists in memory
            if addr not in self.mem.zones:
                raise Exception(
                    "Doing mmprotect on an unexisting memory block")
            # Returns 0 for success
            self.regs['x0'] = 0
        else:
            print('SYSCALL {}({})'.format(
                index, ', '.join(hex(a) for a in args)))
            raise Exception("Not yet implemented syscall")

    def dump_mem(self, fileprefix, directory=None):
        """Dump current memory mapping"""
        directory = directory or os.path.dirname(__file__)
        for base, mem in self.mem.zones.items():
            filename = '{}{:x}.bin'.format(fileprefix, base)
            filename = os.path.join(directory, filename)
            with open(filename, 'wb') as f:
                f.write(mem)
            print("Dumped a memory block (0x{:x}, 0x{:x}) to {}"
                  .format(base, len(mem), filename))

    def dump_instrdesc(self, filename, directory=None):
        """Dump saved instruction descriptions"""
        directory = directory or os.path.dirname(__file__)
        with open(os.path.join(directory, filename), 'w') as f:
            for i, descs in enumerate(self.instrdesc):
                text_instr, params = self.instructions[i]
                if params:
                    text_instr += ' ' + ', '.join(params)
                text_d = ''
                if descs:
                    text_d = '\t'.join('{:20s}'.format(d) for d in descs)
                f.write('  {:6x}:\t{:30s}{}\n'.format(
                    self.base_instr + i * 4,
                    text_instr, text_d))
