#!/usr/bin/env python3
"""Map zones into a virtual memory"""

import os.path
import struct


class MemMap(object):
    """
    >>> m = MemMap()
    >>> m.add_mem(0x1000, 0x1000)
    >>> m.write_uint32(0x1000, 0x01020304)
    >>> m[0x1000]
    4
    >>> bytes(m[0x1000:0x1002]) == b'\\x04\\x03'
    True
    >>> m.get_uint8(0x1002)
    2
    >>> m.get_uint16(0x1002)
    258
    >>> m.write_uint(0x1100, 0x0123456789abcdef, 8)
    >>> hex(m.get_uint64(0x1100)).replace('L', '')
    '0x123456789abcdef'
    >>> hex(m.get_uint(0x1102, 4))
    '0x456789ab'
    """

    def __init__(self):
        self.zones = {}

    def load_mem(self, addr, data):
        """Load data at a given address"""
        assert addr >= 0 and len(data) > 0
        for base, mem in self.zones.items():
            if base < addr + len(data) and base + len(mem) > addr:
                raise Exception(
                    ("Trying to allocate memory (0x{:x}, 0x{:x}) " +
                     "which overlaps (0x{:x}, 0x{:x})")
                    .format(addr, len(data), base, len(mem)))
        self.zones[addr] = bytearray(data)

    def add_mem(self, addr, size):
        """Add a memory zone at a given address for the given size"""
        assert size > 0
        self.load_mem(addr, bytearray(size))

    def del_mem(self, addr):
        """Remove a memory zone, returning its data"""
        data = self.zones[addr]
        del self.zones[addr]
        return data

    def __getitem__(self, addr):
        if isinstance(addr, slice):
            # Get a range [start:stop]
            for base, mem in self.zones.items():
                if base <= addr.start and addr.stop <= base + len(mem):
                    return mem[addr.start - base:addr.stop - base:addr.step]
            raise Exception(
                "Segmentation fault: unable to read {} bytes from 0x{:x}"
                .format(addr.stop - addr.start, addr.start))
        else:
            # Get a byte
            for base, mem in self.zones.items():
                if base <= addr < base + len(mem):
                    return mem[addr - base]
            raise Exception(
                "Segmentation fault: unable to read 1 byte from 0x{:x}"
                .format(addr))

    def __setitem__(self, addr, value):
        # Set a byte
        for base, data in self.zones.items():
            if base <= addr < base + len(data):
                data[addr - base] = value

    def get_uint8(self, addr):
        return int(self[addr])

    def get_uint16(self, addr):
        return struct.unpack('<H', self[addr:addr+2])[0]

    def get_uint32(self, addr):
        return struct.unpack('<I', self[addr:addr+4])[0]

    def get_uint64(self, addr):
        return struct.unpack('<Q', self[addr:addr+8])[0]

    def get_uint(self, addr, size):
        if size == 1:
            return self.get_uint8(addr)
        elif size == 2:
            return self.get_uint16(addr)
        elif size == 4:
            return self.get_uint32(addr)
        elif size == 8:
            return self.get_uint64(addr)
        else:
            raise ValueError(size)

    def write_bytes(self, addr, data):
        for base, mem in self.zones.items():
            if base <= addr and addr + len(data) <= base + len(mem):
                mem[addr - base:addr + len(data) - base] = data
                return
        raise Exception(
            "Segmentation fault: unable to write {} bytes to 0x{:x}"
            .format(len(data), addr))

    def write_uint8(self, addr, value):
        return self.write_bytes(addr, struct.pack('B', value))

    def write_uint16(self, addr, value):
        return self.write_bytes(addr, struct.pack('<H', value))

    def write_uint32(self, addr, value):
        return self.write_bytes(addr, struct.pack('<I', value))

    def write_uint64(self, addr, value):
        return self.write_bytes(addr, struct.pack('<Q', value))

    def write_uint(self, addr, value, size):
        if size == 1:
            return self.write_uint8(addr, value)
        elif size == 2:
            return self.write_uint16(addr, value)
        elif size == 4:
            return self.write_uint32(addr, value)
        elif size == 8:
            return self.write_uint64(addr, value)
        else:
            raise ValueError(size)


if __name__ == '__main__':
    import doctest
    import sys
    sys.exit(1 if doctest.testmod().failed != 0 else 0)
