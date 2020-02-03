/***
 * Author: Nash E. Foster <leaf@pyrofex.net>
 */
#include "breakzip.h"
#include "breakzip_config.h"

#include <time.h>

DEFINE_bool(hexdump, false,
            "After printing relevant info, dump the entire file as hex.");
DEFINE_bool(print_summary, false, "Print the file summary.");

DEFINE_int32(seed_start, 0x56a50000, "Seed to start search.");
DEFINE_int32(seed_end, 0x56a90000, "Seed to end search.");

namespace breakzip {
using namespace std;

const char* usage_message = R"usage(
    -flagfile                   load flags from file     type: string default: ""
    -fromenv                    set flags from the environment [use 'export FLAGS_flag1=value']
                                type: string default: ""
    -tryfromenv                 set flags from the environment if present.
                                type: string default: ""
    -undefok                    comma-separated list of flag names that it is okay to
                                specify on the command line even if the program does not
                                define a flag with that name.  IMPORTANT: flags in this
                                list that have arguments MUST use the flag=value format.
                                type: string default: ""

    -tab_completion_columns     Number of columns to use in output for tab completion
                                type: int32 default: 80
    -tab_completion_word        If non-empty, HandleCommandLineCompletions() will hijack
                                the process and attempt to do bash-style command line flag
                                completion on this value. type: string default: ""

    -help                       Show help on all flags [tip: all flags can have two dashes]
                                type: bool default: false
    -helpfull                   Show help on all flags -- same as -help.
                                type: bool default: false
    -helpmatch                  show help on modules whose name contains the specified substr
                                type: string default: ""
    -helpon                     Show help on the modules named by this flag value.
                                type: string default: ""
    -helppackage                Show help on all modules in the main package.
                                type: bool default: false
    -helpshort                  Show help on only the main module for this program.
                                type: bool default: false
    -helpxml                    Produce an xml version of help. type: bool default: false
    -version                    Show version and build info and exit. type: bool default: false

    -debug                      Enable debugging output. type: bool default: false
    -log_level                  Set the log level. type: int32 default: 3
    )usage";

std::string version_string() {
    ostringstream ss;
    ss << BREAKZIP_VERSION_MAJOR << "." << BREAKZIP_VERSION_MINOR << "."
       << BREAKZIP_VERSION_PATCH << " (c) Pyrofex Corporation. ";
    return move(ss.str());
}

int main(int argc, char* argv[]) {
    auto initok = InitBreakZip(argc, argv);
    if (!initok) {
        fprintf(stderr, "Intiailization failed!\n");
        exit(-1);
    }

    int exit_code = 0;

    ShutdownBreakZip();
    return exit_code;
}

bool InitBreakZip(int argc, char* argv[]) {
    int my_argc = argc;

    google::SetVersionString(version_string());
    google::SetUsageMessage(usage_message);
    auto non_flag = google::ParseCommandLineFlags(&my_argc, &argv, false);

    /* NB(leaf): for now we throw away all non-flag arguments */
    return true;
}

void ShutdownBreakZip() { return; }

EndOfCentralDirectoryRecord::EndOfCentralDirectoryRecord(char* byteptr)
    : ptr_(byteptr),
      eocdr_((struct inner_eocdr*)byteptr),
      comment_((char*)(byteptr + sizeof(struct inner_eocdr))) {
    if (0 == eocdr_->comment_sz) {
        comment_ = nullptr;
    }
}

void EndOfCentralDirectoryRecord::eocdrdump(FILE* f) {
    if (nullptr == eocdr_) {
        fprintf(f, "No end of central directory record!\n");
        return;
    }

    fprintf(f, "----- End of Central Directory Record -----\n");
    fprintf(f, "    Signature: 0x%08x\n", eocdr_->signature);
    fprintf(f, "    disk number:      %d\n", eocdr_->disk_number);
    fprintf(f, "    cdir disk number: %d\n", eocdr_->cdir_disk_number);
    fprintf(f, "    cdir records:     %d\n", eocdr_->cdir_records_on_disk);
    fprintf(f, "    cdir records total:    %d\n", eocdr_->cdir_records_total);
    fprintf(f, "    cdir size:             %d\n", eocdr_->cdir_sz);
    fprintf(f, "    cdir offset:           %d\n", eocdr_->cdir_offset);
    fprintf(f, "    comment length:        %d\n", eocdr_->comment_sz);
    if (0 < eocdr_->comment_sz && nullptr != comment_) {
        fprintf(f, "Comment: %s\n", comment_);
    }

    return;
}

CentralDirectoryRecord::CentralDirectoryRecord(char* byteptr)
    : ptr_(byteptr),
      cdr_((struct inner_cdr*)byteptr),
      filename_((char*)(byteptr + sizeof(struct inner_cdr))),
      extra_((char*)(byteptr + sizeof(struct inner_cdr) + cdr_->filename_len)),
      comment_((char*)(byteptr + sizeof(struct inner_cdr) + cdr_->filename_len +
                       cdr_->extra_len)) {}

void CentralDirectoryRecord::dump(FILE* f) {
    if (nullptr == cdr_) {
        fprintf(f, "No central directory record!\n");
        return;
    }

    fprintf(f, "----- Central Directory Record -----\n");
    fprintf(f, "    CDR Pointer Located @ 0x%p\n", ptr_);
    fprintf(f, "    Signature: 0x%08x\n", cdr_->signature);
    fprintf(f, "    Local File Header Offset: %d\n", cdr_->lfh_offset);
    return;
}

char* CentralDirectoryRecord::next(char* limit) {
    auto n = (char*)cdr_;
    n += sizeof(struct inner_cdr);

    for (auto n = (char*)cdr_ + sizeof(struct inner_cdr); n <= limit; ++n) {
        if (CDIR_SIGNATURE == *(uint32_t*)n) {
            return n;
        }
    }

    return nullptr;
}

LocalFileHeader::LocalFileHeader(char* byteptr)
    : ptr_(byteptr),
      lfh_((struct inner_lfh*)byteptr),
      filename_((char*)(byteptr + sizeof(struct inner_lfh))),
      extra_((char*)(byteptr + sizeof(struct inner_lfh) + lfh_->filename_len)),
      crypt_hdr_(nullptr),
      file_data_(nullptr) {
    auto sig = lfh_->signature;
    if (LOCAL_FILE_HEADER_SIGNATURE == sig) {
        fprintf(stderr, "LFH signature checked out.\n");
    } else {
        fprintf(stderr, "LFH invalid signature!\n");
        abort();
    }

    if (0 != (lfh_->flags & 0x0001)) {
        crypt_hdr_ = extra_ + lfh_->extra_len;
    }

    file_data_ = extra_ + lfh_->extra_len;
    if (0 != crypt_hdr_) {
        file_data_ += 12;  // crypt header is 12 bytes.
    }
}

vector<uint8_t> LocalFileHeader::crypt_header() {
    vector<uint8_t> rval(10);
    if (nullptr != crypt_hdr_) {
        for (int i = 0; i < 10; ++i) {
            rval[i] = (uint8_t)crypt_hdr_[i];
        }
    }
    return std::move(rval);
}

void LocalFileHeader::dump(FILE* f) {
    if (nullptr == lfh_) {
        fprintf(f, "No local file header!\n");
        return;
    }

    fprintf(f, "----- Local File Header -----\n");
    fprintf(f, "    LFH Point Located @ 0x%p\n", ptr_);
    fprintf(f, "    Signature: 0x%08x\n", lfh_->signature);
    fprintf(f, "    Crypt Header Located @ 0x%p\n", crypt_hdr_);
    if (crypt_hdr_) {
        fprintf(f, "    Crypt Header: ");
        for (int i = 0; i < 12; ++i) {
            fprintf(f, "%02x ", ((uint8_t*)crypt_hdr_)[i]);
        }
        fprintf(f, "\n");
    }
}

int recoverseed(int argc, char* argv[]) {
    int my_argc = argc;

    // TODO(leaf): make ones for recoverseed.
    google::SetVersionString(version_string());
    google::SetUsageMessage(usage_message);
    auto non_flag = google::ParseCommandLineFlags(&my_argc, &argv, false);

    if (non_flag >= argc) {
        google::ShowUsageWithFlags(argv[0]);
        exit(-1);
    }

    char* filename = argv[non_flag];
    auto zfile = new ZipFile(filename);

    if (-1 == zfile->init()) {
        fprintf(stderr, "Can't initialize ZipFile: %s\n", strerror(errno));
        return -1;
    }

    if (FLAGS_print_summary) {
        zfile->print_summary(stdout);
    }

    if (FLAGS_hexdump) {
        zfile->hexdump(stdout);
    }

    auto v = zfile->known_seed_bytes();
    fprintf(stderr, "Known random seed bytes: \n");
    int i = 0;
    for (auto b : v) {
        fprintf(stderr, "    %d: %02x\n", i, b);
        i += 10;
    }

    uint32_t start_time = (time_t)FLAGS_seed_start;
    uint32_t end_time = (time_t)FLAGS_seed_end;

    if (start_time >= end_time) {
        fprintf(stderr, "-start_time must be less than -end_time\n");
        return -1;
    }

    uint32_t val = start_time;
    val &= ~0x0000FFFF;  // Clear lower 16 bits.
    fprintf(stdout,
            "Searching for valid seeds. "
            "Starting with 0x%08x.\n",
            val);

    while (val <= end_time) {
        if (0 == (val & 0x0FFF)) {
            fprintf(stderr, "    ... 0x%08x\n", val);
        }

        srand(val);
        vector<uint8_t> t;

        for (int j = 0; j <= 10; ++j) {
            t.push_back((uint8_t)((rand() >> 7) & 0xff));
        }

        if (v[0] == t[0] && v[1] == t[10]) {
            fprintf(stdout, "    Valid seed: 0x%08x\n", val);
        }

        ++val;
    }

    fprintf(stdout, "Searching ended with seed 0x%08x\n", val);

    zfile->close();
    return 0;
}

ZipFile::ZipFile(std::string filename) : filename_(filename){};

/***
 * ZipFile::init() causes the ZipFile object to initialize itself.
 * The underlying file is opened, if possible. It is then memory mapped.
 * And, finally the central directory is scanned and information about
 * the archive is summarized in private members.
 *
 * Return Value:
 *   0 - if everything completed correctly and the ZipFile object is
 *       ready for use.
 *  -1 - when an error occurred. And error will be printed to stderr
 *       and errno should be set to the underlying system error causing
 *       the failure.
 */
int ZipFile::init() {
    // Open the file, get it's stats.
    if (-1 == (fd_ = open(filename_.c_str(), O_RDONLY))) {
        fprintf(stderr, "Could't open file: %s: %s\n", filename_.c_str(),
                strerror(errno));
        return -1;
    }

    if (-1 == fstat(fd_, &filestats_)) {
        perror("Could't stat file descriptor");
        return -1;
    }

    // Memory map the file.
    mapped_ = mmap(NULL, filestats_.st_size, PROT_READ, MAP_PRIVATE, fd_, 0);
    if (MAP_FAILED == mapped_) {
        perror("Failed to memory map file");
        return -1;
    }

    // Scan for the end of central directory record.
    //   - Ignoring the comment at the end, the EOCDR must be at least 22
    //     bytes long:
    //          End of central directory record (EOCD)
    //          Offset  Bytes   Description[26]
    //          0       4   End of central directory signature = 0x06054b50
    //          4       2   Number of this disk
    //          6       2   Disk where central directory starts
    //          8       2   Number of central directory records on this disk
    //          10      2   Total number of central directory records
    //          12      4   Size of central directory (bytes)
    //          16      4   Offset of start of central directory,
    //                      relative to start of archive
    //          20      2   Comment length (n)
    //          22      n   Comment
    //
    // We start 22 bytes from the end of the file and scan backwards looking
    // for the EOCDR signature (32 bit uint).
    bool eocdr_found = false;
    off_t n = filestats_.st_size - 22;
    for (char* byteptr = (char*)mapped_ + n; byteptr >= mapped_; --byteptr) {
        uint32_t s = *(uint32_t*)byteptr;
        if (END_CDIR_SIGNATURE == s) {
            // Found signature.
            fprintf(stderr, "Found EOCDR at %p\n", byteptr);

            eocdr_ = new EndOfCentralDirectoryRecord(byteptr);
            eocdr_found = true;
            break;
        }
    }

    if (!eocdr_found) {
        fprintf(stderr,
                "Zip File corrupted: Couldn't find end of "
                "central directory record.");
        return -1;
    }

    char* ptr = (char*)mapped_ + eocdr_->cdir_offset();
    char* eocdr_base = eocdr_->base();

    fprintf(stderr, "Mapped @ 0x%p of length %ld.\n", mapped_,
            filestats_.st_size);
    fprintf(stderr, "Last byte in file @ 0x%p\n",
            (char*)mapped_ + filestats_.st_size);
    fprintf(stderr, "End of CDR record @ 0x%p\n", eocdr_base);
    fprintf(stderr,
            "Central directory record @ 0x%p, "
            "offset %d\n",
            ptr, eocdr_->cdir_offset());

    fprintf(stderr, "Is ptr < eocdr_? %s\n", (ptr < eocdr_base ? "yes" : "no"));

    while (ptr < eocdr_base) {
        auto cdr = new CentralDirectoryRecord(ptr);
        if (cdr->check_signature()) {
            fprintf(stderr, "Found CDR at 0x%p (EOCDR @ 0x%p)\n", ptr,
                    eocdr_base);
            cdrs_.push_back(cdr);
            cdr->dump(stderr);
            if (nullptr == (ptr = cdr->next(eocdr_base))) {
                break;
            }
        } else {
            delete cdr;
            break;
        }
    }

    fprintf(stderr,
            "Found %ld central directory records of "
            "%d EOCDR total.\n",
            cdrs_.size(), eocdr_->cdir_records_total());

    for (auto cdr : cdrs_) {
        auto lfh_offset = cdr->lfh_offset();
        if (lfh_offset > filestats_.st_size) {
            fprintf(stderr,
                    "Invalid LFH offset %d is greater than file size %ld.\n",
                    lfh_offset, filestats_.st_size);
            return -1;
        }

        auto p = (char*)mapped_ + lfh_offset;
        fprintf(stderr, "Createing LFH at 0x%p\n: offset=%d of %ld total.\n", p,
                lfh_offset, filestats_.st_size);
        auto lfh = new LocalFileHeader(p);
        if (!lfh->check_signature()) {
            fprintf(stderr,
                    "Local File Header corrupted: "
                    "invalid signature.\n");
            break;
        }
        fprintf(stderr, "...\n");
        lfhs_.push_back(lfh);
        lfh->dump(stderr);
    }

    return 0;
}

std::vector<LocalFileHeader*> ZipFile::local_file_headers() {
    std::vector<LocalFileHeader*> rval(2);

    for (int i = 0; i < 2; ++i) {
        rval[i] = this->lfhs_[i];
    }

    return std::move(rval);
}

/***
 * The first byte of every crypt_hdr that follows a LocalFileHeader is
 * encrypted twice with the same crypt state, which means its plaintext.
 * The known_seed_bytes method returns these in a vector.
 */
std::vector<uint8_t> ZipFile::known_seed_bytes() {
    std::vector<uint8_t> v;
    for (auto l : this->lfhs_) {
        auto c = *(l->crypt_hdr());
        v.push_back(c);
    }
    return std::move(v);
}

/***
 * Close the ZipFile.
 */
void ZipFile::close() {
    if (-1 == ::munmap(mapped_, filestats_.st_size)) {
        fprintf(stderr, "Can't unmap file: %s\n", strerror(errno));
        exit(4);
    }

    if (-1 == ::close(fd_)) {
        fprintf(stderr, "Can't close file: %s\n", strerror(errno));
        exit(5);
    }

    return;
}

/***
 * Print a full hexdump to the FILE.
 */
void ZipFile::hexdump(FILE* f) {
    const int bytes_per_line = 20;
    unsigned char* byteptr = (unsigned char*)mapped_;
    for (int n = 0; n < filestats_.st_size; ++n) {
        fprintf(f, "%02x", byteptr[n]);
        if (3 == n % 4) {
            fprintf(f, "  ");
        } else {
            fprintf(f, " ");
        }

        if (bytes_per_line - 1 == n % bytes_per_line) {
            fprintf(f, "\n");
        }
    }

    fprintf(f, "\n");
}

void ZipFile::print_summary(FILE* f) {
    fprintf(f, "ZipFile Filename: %s\n", filename_.c_str());
    if (eocdr_) {
        eocdr_->eocdrdump(f);
    }
}

};  // namespace breakzip
