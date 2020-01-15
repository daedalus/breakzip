#ifndef CRC32_H
#define CRC32_H

extern const uint32_t crc32tab[256];
extern const uint8_t crcinvtab[256];

uint32_t crc32(uint32_t x, uint8_t y);

#endif
