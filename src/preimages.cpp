#include <stdio.h>
#include <stdlib.h>

#include "breakzip.h"
#include "breakzip_config.h"
#include "crc32.h"
#include "mitm_common.h"

DECLARE_string(target);
DECLARE_bool(runtests);
DEFINE_string(input_shard, "target.out.0",
              "The filename of the stage1 shard to run on.");
DECLARE_string(output);
DECLARE_int32(srand_seed);
DEFINE_int32(stop_after, -1,
             "If set to a positive value, the program "
             "will stop after processing <stop_after> stage1 candidates.");

using namespace mitm;
using namespace std;
using namespace breakzip;
using namespace google;

const char* usage_message = R"usage(
    Usage: preimages
    Builds the preimages table and outputs a C definition of it.
    )usage";

int main(int argc, char* argv[]) {
    int my_argc = argc;

    SetVersionString(version_string());
    SetUsageMessage(usage_message);
    auto non_flag = ParseCommandLineFlags(&my_argc, &argv, false);

    // We build the preimages once for all candidates.
    vector<vector<uint16_t>> preimages(0x100);
    build_preimages(preimages);

    printf("const uint16_t preimages[256][64] = {\n");
    for (int i = 0; i < preimages.size(); ++i) {
        printf("    {");
        for (int j = 0; j < preimages[i].size(); ++j) {
            printf("%d, ", preimages[i][j]);
        }
        printf("},\n");
    }
    printf("};\n");

    return 0;
}
