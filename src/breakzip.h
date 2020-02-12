/***
 * Author: Nash E. Foster <leaf@pyrofex.net>
 */
#ifndef __BREAKZIP_H__
#define __BREAKZIP_H__

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <gflags/gflags.h>

#include "breakzip_config.h"
#include "crc32.h"
#include "mitm_common.h"
#include "mitm_stage1/mitm_stage1.h"
#include "mitm_stage2/mitm_stage2.h"
#include "preimages_table.h"
#include "types.h"

// Avoid structure padding
#pragma pack(1)

#define END_CDIR_SIGNATURE 0x06054b50
#define CDIR_SIGNATURE 0x02014b50
#define DATA_DESCRIPTOR_SIGNATURE 0x08074b50
#define LOCAL_FILE_HEADER_SIGNATURE 0x04034b50

/* The internal ZIP crypto constant */
#define CRYPTCONST 0x08088405
#define CRYPTCONST_POW2 0xd4652819
#define CRYPTCONST_POW3 0x576eac7d
#define CRYPTCONST_POW4 0x1201d271
#define CRYPTCONST_INV 0xd94fa8cd

#define LSB(x) (x & 0xff)

namespace breakzip {

std::string version_string();

int main(int argc, char* argv[]);
bool InitBreakZip(int argc, char* argv[]);
void ShutdownBreakZip();
int recoverseed(int argc, char* argv[]);

struct EndOfCentralDirectoryRecord {
public:
    EndOfCentralDirectoryRecord(char* byteptr);

    char* base() { return ptr_; }
    unsigned int signature() { return eocdr_->signature; }
    unsigned short disk_number() { return eocdr_->disk_number; }
    unsigned short cdir_disk_number() { return eocdr_->cdir_disk_number; }
    unsigned short cdir_records_on_disk() {
        return eocdr_->cdir_records_on_disk;
    }
    unsigned short cdir_records_total() { return eocdr_->cdir_records_total; }
    unsigned int cdir_sz() { return eocdr_->cdir_sz; }
    unsigned int cdir_offset() { return eocdr_->cdir_offset; }
    unsigned short comment_sz() { return eocdr_->comment_sz; }
    char* comment() { return comment_; }

    void eocdrdump(FILE* f);

private:
    struct inner_eocdr {
        unsigned int signature;
        unsigned short disk_number;
        unsigned short cdir_disk_number;
        unsigned short cdir_records_on_disk;
        unsigned short cdir_records_total;
        unsigned int cdir_sz;
        unsigned int cdir_offset;
        unsigned short comment_sz;
    };

    char* ptr_;
    struct inner_eocdr* eocdr_;
    char* comment_;
};

struct CentralDirectoryRecord {
    CentralDirectoryRecord(char* byteptr);
    void dump(FILE* f);
    char* next(char* limit);
    char* base() { return ptr_; }
    bool check_signature() { return (CDIR_SIGNATURE == cdr_->signature); }
    unsigned int signature() { return cdr_->signature; }
    unsigned int lfh_offset() { return cdr_->lfh_offset; }

private:
    struct inner_cdr {
        uint32_t signature;             // 4 bytes (0)
        uint16_t version_made_by;       // 2 bytes (4)
        uint16_t version_for_extract;   // 2 bytes (6)
        uint16_t flags;                 // 2 bytes (8)
        uint16_t comp_method;           // 2 bytes (10)
        uint16_t file_modified_time;    // 2 bytes (12)
        uint16_t file_modified_date;    // 2 bytes (14)
        uint32_t crc32;                 // 4 bytes (16)
        uint32_t compressed_sz;         // 4 bytes (20)
        uint32_t uncompressed_sz;       // 4 bytes (24)
        uint16_t filename_len;          // 2 bytes (26)
        uint16_t extra_len;             // 2 bytes (28)
        uint16_t comment_len;           // 2 bytes (30)
        uint16_t file_starts_disk_num;  // 2 bytes (32)
        uint16_t file_attrs;            // 2 bytes (34)
        uint32_t external_file_attrs;   // 4 bytes (38)
        uint32_t lfh_offset;            // 4 bytes (42)
    };                                  // sizeof == 46

    char* ptr_;
    struct inner_cdr* cdr_;
    char* filename_;
    char* extra_;
    char* comment_;
};

struct LocalFileHeader {
    LocalFileHeader(char* byteptr);

    void dump(FILE* f);
    char* base() { return ptr_; }
    bool check_signature() {
        return (LOCAL_FILE_HEADER_SIGNATURE == lfh_->signature);
    }

    char* crypt_hdr() { return crypt_hdr_; }
    std::vector<uint8_t> crypt_header();

private:
    struct inner_lfh {
        unsigned int signature;
        unsigned short version_for_extract;
        unsigned short flags;
        unsigned short comp_method;
        unsigned short file_modified_time;
        unsigned short file_modified_date;
        unsigned int crc32;
        unsigned int compressed_sz;
        unsigned int uncompressed_sz;
        unsigned short filename_len;
        unsigned short extra_len;
    };

    char* ptr_;
    struct inner_lfh* lfh_;
    char* filename_;
    char* extra_;
    char* crypt_hdr_;
    char* file_data_;
};

class ZipFile {
public:
    ZipFile(std::string filename);

    int init();
    void close();
    void hexdump(FILE* f);
    void print_summary(FILE* f);
    std::vector<uint8_t> known_seed_bytes();
    std::vector<LocalFileHeader*> local_file_headers();

private:
    EndOfCentralDirectoryRecord* eocdr_;
    const std::string filename_;
    int fd_;
    struct stat filestats_;
    void* mapped_;

    std::vector<CentralDirectoryRecord*> cdrs_;
    std::vector<LocalFileHeader*> lfhs_;
};

};  // namespace breakzip

#endif
