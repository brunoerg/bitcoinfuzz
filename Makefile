CXX      =  clang++
HEADERS :=  $(wildcard $(shell find bitcoin -type f -name '*.h')) compiler.h targets/bech32.h targets/tx_des.h targets/miniscript_policy.h targets/miniscript_string.h targets/block_des.h targets/prefilledtransaction.h
SOURCES :=  $(wildcard $(shell find bitcoin -type f -name '*.cpp')) compiler.cpp targets/bech32.cpp targets/tx_des.cpp targets/miniscript_policy.cpp targets/miniscript_string.cpp targets/block_des.cpp targets/prefilledtransaction.cpp
OBJS    :=  $(patsubst %.cpp, build/%.o, $(SOURCES))
UNAME_S :=  $(shell uname -s)
CXXFLAGS := -O3 -g0 -Wall -fsanitize=fuzzer -DHAVE_GMTIME_R=1 -std=c++20 -march=native -Ibitcoin
LDFLAGS :=  -L rust_bitcoin_lib/target/debug -L btcd_lib -lbtcd_wrapper -lrust_bitcoin_lib -lpthread -ldl

ifeq ($(UNAME_S),Darwin)
LDFLAGS += -framework CoreFoundation -Wl,-ld_classic
endif

bitcoinfuzz: set $(OBJS) cargo go
	$(CXX) fuzzer.cpp -o $@ $(OBJS) $(CXXFLAGS) $(LDFLAGS)

$(OBJS) : build/%.o: %.cpp
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CXX) -c $(CXXFLAGS) $< -o $@

cargo:
	cd rust_bitcoin_lib && cargo rustc -- -C passes='sancov-module' \
	-C llvm-args='-sanitizer-coverage-inline-8bit-counters' \
	-C llvm-args='-sanitizer-coverage-trace-compares' \
	-C llvm-args='-sanitizer-coverage-pc-table' \
	-C llvm-args='-sanitizer-coverage-level=3'

go:
	cd dependencies/btcd/wire && go build -tags=libfuzzer -gcflags=all=-d=libfuzzer .
	cd btcd_lib && go build -o libbtcd_wrapper.a -buildmode=c-archive -tags=libfuzzer -gcflags=all=-d=libfuzzer wrapper.go

clean:
	rm -f bitcoinfuzz $(OBJS) btcd_lib/libbtcd_wrapper.*
	rm -Rdf rust_bitcoin_lib/target

set:
	@$(if $(strip $(BTCD)), cd dependencies/btcd && git fetch origin master && git checkout $(BTCD))
	@$(if $(strip $(RUST_BITCOIN)), cd dependencies/rust-bitcoin && git fetch origin master && git checkout $(RUST_BITCOIN))
