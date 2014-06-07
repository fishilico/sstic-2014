void decrypt(uint64_t key)
{
    uint8_t *data = (uint8_t *) 0x8000;
    uint16_t r1;
    for (r1 = 0; r1 < 0x2000; r1 ++) {
        uint8_t r4 = 0;
        uint8_t r3;
        for (r3 = 8; r3 != 0; r3 --) {
            uint32_t r8 = ((key >> 32) & 0xb0000000) ^ (key & 1);
            key >>= 1;
            if (__builtin_parity(r8)) {
                key |= 1ULL << 63;
            }
            r4 |= (key & 1) << (r3 - 1);
        }
        data[r1] ^= r4;
    }
}
