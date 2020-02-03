/***
 * Author: Nash E. Foster <leaf@pyrofex.net>
 */

#ifndef __BREAKZIP_TYPES__
#define __BREAKZIP_TYPES__

#include <cstdint>
#include <cstring>
#include <string>

#define ZIP_LOCAL_FILE_HEADER_SIGNATURE 0x04034b50
#define ZIP_VERSION_MAJOR(x) (x / 10)
#define ZIP_VERSION_MINOR(x) (x % 10)

namespace breakzip {};  // namespace breakzip

#endif
