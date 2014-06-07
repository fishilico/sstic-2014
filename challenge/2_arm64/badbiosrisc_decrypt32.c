void decrypt(uint64_t key)
{
    uint8_t *data = (uint8_t *) 0x8000;
    uint32_t r10 = (key >> 32) & 0xffffffff;
    uint32_t r11 = key & 0xffffffff;
    uint16_t r1;
    for (r1 = 0; r1 < 0x2000; r1 ++) {
        uint8_t r4 = 0;
        uint8_t r3;
        for (r3 = 8; r3 != 0; r3 --) {
            uint32_t r8 = (r10 & 0xb0000000) ^ (r11 & 1);
            r8 = __builtin_parity(r8) ? 1 : 0;
            r11 = (r11 >> 1) | ((r10 & 1) << 31);
            r10 = (r10 >> 1) | (r8 << 31);
            r4 |= (r11 & 1) << (r3 - 1);
        }
        data[r1] ^= r4;
    }
}
