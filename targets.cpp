#include <fuzzer/FuzzedDataProvider.h>
#include <script/miniscript.h>
#include <string>

#include "targets.h"
#include "compiler.h"

extern "C" bool miniscript_str_parse(std::string& miniscript_str);

void MiniscriptStringParse(FuzzedDataProvider& provider) {
    auto input_str{provider.ConsumeBytesAsString(provider.remaining_bytes() - 1)};
    (void)(miniscript_str_parse(input_str));
    (void)miniscript::FromString(input_str, COMPILER_CTX);
}