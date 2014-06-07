#!/usr/bin/env python3

import binascii
import struct


# Extract transmitted data
xdata = b''
with open('usbtrace', 'r') as f:
    is_extracting = False
    for linenum, line in enumerate(f):
        if linenum < 12:
            continue
        parts = line.rstrip().split(' ', 7)
        if len(parts) <= 7:
            continue
        if parts[3] != 'Bo:2:008:3':
            continue

        hexadata = parts[7].replace(' ', '')
        data = binascii.unhexlify(hexadata)
        size = int(parts[5])
        assert size == len(data)

        if data[:4] == b'WRTE' and size == 24:
            continue
        elif not is_extracting:
            if data.startswith(b'SEND!'):
                is_extracting = True
        elif data.startswith(b'shell:chmod'):
            is_extracting = False
        else:
            xdata += data

# Retrieve chunks and write badbios.bin
prefix = b'/data/local/tmp/badbios.bin,33261'
assert xdata.startswith(prefix)
xdata = xdata[len(prefix):]
with open('badbios.bin', 'wb') as fout:
    while xdata.startswith(b'DATA'):
        chunck_size = struct.unpack('<I', xdata[4:8])[0]
        assert 8 + chunck_size <= len(xdata)
        fout.write(xdata[8:8 + chunck_size])
        xdata = xdata[8 + chunck_size:]

assert xdata.startswith(b'DONE')
