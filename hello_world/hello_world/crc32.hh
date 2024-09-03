#ifndef CRC32_HEADER
#define CRC32_HEADER

#include <cstdint>

namespace Utility {
    int64_t Crc32Compute(const void*, int);
};

#endif // crc32.hh