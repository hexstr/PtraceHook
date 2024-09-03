#include "crc32.hh"

#include <zlib.h>

namespace Utility {
    int64_t Crc32Compute(const void* buf, int size) {
        return crc32(0, reinterpret_cast<const unsigned char*>(buf), size);
    }
} // namespace Utility