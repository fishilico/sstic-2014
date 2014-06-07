#!/usr/bin/env python3

import binascii

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
        if int(parts[5]) != len(data):
            print("Invalid size in line: {}".format(line))
            break
        reprdata = ''.join(
            chr(c) if 32 <= c < 127 else
            ('\\0' if c == 0 else '\\x{:02x}'.format(c))
            for c in data)
        print(direction + ' ' + reprdata)
