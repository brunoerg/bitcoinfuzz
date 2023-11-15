#ifndef TARGETS_H
#define TARGETS_H

#include <fuzzer/FuzzedDataProvider.h>
#include <string>

void MiniscriptPolicy(FuzzedDataProvider& provider);
#endif