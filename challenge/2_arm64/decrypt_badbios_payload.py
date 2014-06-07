#!/usr/bin/env python3
"""Decrypt the encrypted data in badbios-decrypt.bin"""

import os.path

HEXKEY = '0BADB10515DEAD11'

# Load encrypted data
curdir = os.path.dirname(__file__)
progname = os.path.join(curdir, 'badbios-decrypt.bin')
with open(progname, 'rb') as f:
    data = bytearray(f.read()[0x8000:0xa000])
assert len(data) == 0x2000

# Load the key into a number
hexkey = ''.join(HEXKEY[2 * i:2 * i + 2] for i in (3, 2, 1, 0, 7, 6, 5, 4))
key = int(hexkey, 16)

# Decrypt data
r10 = (key >> 32) & 0xffffffff
r11 = key & 0xffffffff

for r1 in range(len(data)):
    r4 = 0
    for r3 in range(8, 0, -1):
        r8 = (r10 & 0xb0000000) ^ (r11 & 1)
        # Implement parity(r8) using logic operations
        r8 ^= r8 >> 1
        r8 ^= r8 >> 2
        r8 = ((r8 & 0x11111111) * 0x11111111) >> 28
        r11 = (r11 >> 1) | ((r10 & 1) << 31)
        r10 = (r10 >> 1) | ((r8 & 1) << 31)
        r4 |= (r11 & 1) << (r3 - 1)
    data[r1] ^= r4

# Verify padding
i = len(data) - 1
while not data[i]:
    i -= 1
if i >= len(data) - 8 or data[i] != 0x80:
    print("Invalid padding!")
else:
    with open('payload.bin', 'wb') as f:
        f.write(data[:i])
