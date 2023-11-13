#ifndef TARGETS_H
#define TARGETS_H

#include <fuzzer/FuzzedDataProvider.h>
#include <string>

void MiniscriptStringParse(FuzzedDataProvider& provider);
#endif