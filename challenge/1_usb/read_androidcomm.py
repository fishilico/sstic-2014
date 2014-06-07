#!/usr/bin/env python3

import binascii
import struct

with open('usbtrace', 'r') as f:
    for linenum, line in enumerate(f):
        if linenum < 12:
            continue
        parts = line.rstrip().split(' ', 7)
        if len(parts) <= 7:
            continue

        if parts[3] == 'Bo:2:008:3':
            direction = '>'
        elif parts[3] == 'Bi:2:008:5':
            direction = '<'
        else:
            continue

        hexadata = parts[7].replace(' ', '')
        data = binascii.unhexlify(hexadata)
        size = int(parts[5])
        assert size == len(data)
        if size == 24 and data[:4] in (b'OPEN', b'WRTE', b'OKAY', b'CLSE'):
            continue
        elif size == 8 and data[:4] == b'QUIT':
            continue
        elif size == 6 and data == b'sync:\0':
            continue
        elif size == 8 and data[:4] == b'LIST':
            data = data[:4]
        elif size >= 20 and data[:4] == b'DENT':
            while len(data) >= 20:
                dent_size = struct.unpack('<I', data[16:20])[0]
                assert dent_size > 0
                dent_name = data[20:20 + dent_size].decode('ascii')
                print(direction + ' DENT ' + dent_name)
                data = data[20 + dent_size:]
            continue
        data = data.rstrip(b'\0')
        reprdata = ''.join(
            chr(c) if 32 <= c < 127 else
            ('\\0' if c == 0 else '\\x{:02x}'.format(c))
            for c in data)
        if len(reprdata) >= 85:
            reprdata = reprdata[:85] + '...'
        print(direction + ' ' + reprdata)
