CXX      =  clang++
SOURCES :=  $(wildcard $(shell find bitcoin -type f -name '*.cpp')) targets/bech32.cpp targets/tx_des.cpp targets/miniscript_string.cpp targets/block_des.cpp targets/prefilledtransaction.cpp
INCLUDES =  bitcoin bitcoin/secp256k1/include
LIB_DIR  =  bitcoin/secp256k1/.libs rust_bitcoin_lib/target/debug btcd_lib
OBJS    :=  $(patsubst %.cpp, build/%.o, $(SOURCES))
UNAME_S :=  $(shell uname -s)
INCPATHS:=  $(foreach dir,$(INCLUDES),-I$(dir))
LIBPATHS:=  $(foreach lib,$(LIB_DIR),-L$(lib))
CXXFLAGS:=  -O3 -g0 -Wall -fsanitize=fuzzer -DHAVE_GMTIME_R=1 -std=c++20 -march=native $(INCPATHS)
ORIGLDFLAGS := $(LDFLAGS) # need to save a copy of ld flags as these get modified below
LDFLAGS :=  $(LIBPATHS) -lbtcd_wrapper -lrust_bitcoin_lib -lsecp256k1 -lpthread -ldl

ifeq ($(UNAME_S),Darwin)
LDFLAGS += -framework CoreFoundation -Wl,-ld_classic
endif

bitcoinfuzz: set $(OBJS) libsecp256 cargo go
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

libsecp256:
	cd bitcoin/secp256k1 && \
	(test ! -f "Makefile" && \
	./autogen.sh && \
	LDFLAGS=$(ORIGLDFLAGS) ./configure --enable-module-schnorrsig --enable-benchmark=no --enable-module-recovery \
	--enable-static --disable-shared --enable-tests=no --enable-ctime-tests=no --enable-benchmark=no) || :
	cd bitcoin/secp256k1 && make

go:
	cd dependencies/btcd/wire && go build -tags=libfuzzer -gcflags=all=-d=libfuzzer .
	cd btcd_lib && go build -o libbtcd_wrapper.a -buildmode=c-archive -tags=libfuzzer -gcflags=all=-d=libfuzzer wrapper.go

clean:
	rm -f bitcoinfuzz $(OBJS) btcd_lib/libbtcd_wrapper.*
	rm -Rdf rust_bitcoin_lib/target

set:
	@$(if $(strip $(BTCD)), cd dependencies/btcd && git fetch origin && git checkout $(BTCD))
	@$(if $(strip $(RUST_BITCOIN)), cd dependencies/rust-bitcoin && git fetch origin && git checkout $(RUST_BITCOIN))
	@$(if $(strip $(RUST_MINISCRIPT)), cd dependencies/rust-miniscript && git fetch origin && git checkout $(RUST_MINISCRIPT))
