/* Copyright (c) 2019, Pyrofex Corporation.
 * Author: Nash E. Foster <leaf@pyrofex.net>
 */

#include <cstdint>
#include <string>

namespace zip {

    typedef struct zip_file {

    } zip_file_t;

    struct LocalFileHeader {
        public:
            explicit LocalFileHeader(uint8_t* data)
                : hdr((InnerFileHeader*)data),
                filename((uint8_t*) (data + sizeof(hdr))),
                extra_field((uint8_t*) (data + sizeof(hdr) + hdr->filename_sz))
            {}

            uint32_t signature() const { return hdr->signature; }
            uint16_t version() const { return hdr->version; }
            uint16_t flags() const { return hdr->flags; }
            uint16_t compression_method const { return hdr->flags; }
            uint16_t last_modified_time const { return hdr->last_modified_time; }

        private:

            struct InnerFileHeader {
                uint32_t signature = 0x04034b50;
                uint16_t version = 0;
                uint16_t flags = 0;
                uint16_t compression_method = 0;
                uint16_t last_modified_time = 0;
                uint16_t last_modified_date = 0;
                uint32_t crc32 = 0;
                uint32_t compressed_sz = 0;
                uint32_t uncmopressed_sz = 0;
                uint16_t filename_sz = 0;
                uint16_t extra_field_sz = 0;
            };

            InnerFileHeader* hdr;
            unsigned char* filename;
            uint8_t* extra_field;
    };

};


}; // namespace
