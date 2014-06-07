#!/usr/bin/env python3
"""Find the key of badbios-decrypt.bin"""

import os.path
import sys

# Load encrypted data
curdir = os.path.dirname(__file__)
progname = os.path.join(curdir, 'badbios-decrypt.bin')
with open(progname, 'rb') as f:
    data = f.read()[0x8000:0xa000]

# Equations of each bit of r10r11 depending on the bits of the key
# a_{i,j,l} is bit l of k_equ[j]
k_equ = [1 << i for i in range(0, 64)]

# Equations in a triangular form
triangular_system = [None] * 64
triangular_system_vals = [None] * 64

for r1 in range(0x2000):
    r4_bits = [0] * 8
    for r3 in range(8, 0, -1):
        equ63 = k_equ[63] ^ k_equ[61] ^ k_equ[60] ^ k_equ[0]
        for i in range(0, 63):
            k_equ[i] = k_equ[i + 1]
        k_equ[63] = equ63

        if r1 >= 0x2000 - 8:
            # The padding is 0 so here r4 = data[i]
            r4_bit_equ = k_equ[0]
            r4_bit_value = (data[r1] >> (r3 - 1)) & 1
            # Simplify equation with the triangular system
            while r4_bit_equ:
                msb = r4_bit_equ.bit_length() - 1
                if triangular_system[msb] is not None:
                    # XOR each part of the equation
                    r4_bit_equ ^= triangular_system[msb]
                    r4_bit_value ^= triangular_system_vals[msb]
                    assert r4_bit_equ.bit_length() - 1 < msb
                else:
                    # Insert a new equation
                    triangular_system[msb] = r4_bit_equ
                    triangular_system_vals[msb] = r4_bit_value
                    break

# Make the system diagonal, if possible, and recover the key
key = 0
for i in range(64):
    if triangular_system[i] is None:
        print("Unable to find the key :(")
        sys.exit(1)
    assert triangular_system[i] == (1 << i)
    key |= triangular_system_vals[i] << i
    for j in range(i + 1, 64):
        if triangular_system[j] & (1 << i):
            triangular_system[j] ^= triangular_system[i]
            triangular_system_vals[j] ^= triangular_system_vals[i]

# Reorder bytes : input "0001020304050607" is encoded 0x0302010007060504
hexkey = '{:016X}'.format(key)
hexkey = ''.join(hexkey[2 * i:2 * i + 2] for i in (3, 2, 1, 0, 7, 6, 5, 4))
print(hexkey)
