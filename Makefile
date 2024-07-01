CXX      =  clang++
CC       =  clang
SOURCES :=  $(wildcard $(shell find targets -type f -name '*.cpp'))
INCLUDES =  dependencies/ dependencies/bitcoin/src/ dependencies/bitcoin/src/secp256k1/include
LIB_DIR  =  dependencies/bitcoin/src/ dependencies/bitcoin/src/.libs dependencies/bitcoin/src/secp256k1/.libs rust_bitcoin_lib/target/debug btcd_lib
OBJS    :=  $(patsubst %.cpp, build/%.o, $(SOURCES))
UNAME_S :=  $(shell uname -s)
INCPATHS:=  $(foreach dir,$(INCLUDES),-I$(dir))
LIBPATHS:=  $(foreach lib,$(LIB_DIR),-L$(lib))
CXXFLAGS:=  -O3 -g0 -Wall -fsanitize=fuzzer -DHAVE_GMTIME_R=1 -std=c++20 -march=native $(INCPATHS)
ORIGLDFLAGS := $(LDFLAGS) # need to save a copy of ld flags as these get modified below
LDFLAGS :=  $(LIBPATHS) -lbtcd_wrapper -lrust_bitcoin_lib -lbitcoin_common -lbitcoin_util -lbitcoinkernel -lsecp256k1 -lpthread -ldl

ifeq ($(UNAME_S),Darwin)
LDFLAGS += -framework CoreFoundation -Wl,-ld_classic
endif

.PHONY: bitcoinfuzz bitcoin cargo go clean

bitcoinfuzz: set $(OBJS) bitcoin cargo go
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

bitcoin:
	cd dependencies/bitcoin && \
	(test ! -f "Makefile" && \
	./autogen.sh &&  \
	CXX=$(CXX) CC=$(CC) ./configure --with-daemon=no --disable-wallet --disable-tests --disable-gui-tests --with-gui=no --disable-bench \
	--with-utils=no --enable-static --disable-hardening --disable-shared --with-experimental-kernel-lib --with-sanitizers=fuzzer) || :
	cd dependencies/bitcoin && $(MAKE)

go:
	cd dependencies/btcd/wire && go build -tags=libfuzzer -gcflags=all=-d=libfuzzer .
	cd btcd_lib && go build -o libbtcd_wrapper.a -buildmode=c-archive -tags=libfuzzer -gcflags=all=-d=libfuzzer wrapper.go

clean:
	rm -f bitcoinfuzz $(OBJS) btcd_lib/libbtcd_wrapper.*
	rm -Rdf rust_bitcoin_lib/target
	cd dependencies/bitcoin && git clean -fxd

set:
	@$(if $(strip $(CORE)), cd dependencies/bitcoin && git fetch origin && git checkout $(CORE))
	@$(if $(strip $(BTCD)), cd dependencies/btcd && git fetch origin && git checkout $(BTCD))
	@$(if $(strip $(RUST_BITCOIN)), cd dependencies/rust-bitcoin && git fetch origin && git checkout $(RUST_BITCOIN))
	@$(if $(strip $(RUST_MINISCRIPT)), cd dependencies/rust-miniscript && git fetch origin && git checkout $(RUST_MINISCRIPT))
