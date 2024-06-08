CXX      =  clang++
HEADERS :=  $(wildcard $(shell find bitcoin -type f -name '*.h')) compiler.h targets/bech32.h targets/tx_des.h targets/miniscript_policy.h targets/miniscript_string.h targets/block_des.h targets/prefilledtransaction.h
SOURCES :=  $(wildcard $(shell find bitcoin -type f -name '*.cpp')) compiler.cpp targets/bech32.cpp targets/tx_des.cpp targets/miniscript_policy.cpp targets/miniscript_string.cpp targets/block_des.cpp targets/prefilledtransaction.cpp
OBJS    :=  $(patsubst %.cpp, build/%.o, $(SOURCES))
UNAME_S :=  $(shell uname -s)
CXXFLAGS := -O3 -g0 -Wall -fsanitize=fuzzer -DHAVE_GMTIME_R=1 -std=c++20 -march=native -Ibitcoin
LDFLAGS :=  -L rust_bitcoin_lib/target/release -L btcd_lib -lbtcd_wrapper -lrust_bitcoin_lib -lpthread -ldl

ifeq ($(UNAME_S),Darwin)
LDFLAGS += -framework CoreFoundation -Wl,-ld_classic
endif

bitcoinfuzz: $(OBJS) cargo go
	$(CXX) fuzzer.cpp -o $@ $(OBJS) $(CXXFLAGS) $(LDFLAGS)

$(OBJS) : build/%.o: %.cpp
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CXX) -c $(CXXFLAGS) $< -o $@

cargo:
	cd rust_bitcoin_lib && cargo build --release && cd ..

go:
	cd btcd_lib && go build -o libbtcd_wrapper.a -buildmode=c-archive wrapper.go

clean:
	rm -f bitcoinfuzz $(OBJS) btcd_lib/libbtcd_wrapper.*
	rm -Rdf rust_bitcoin_lib/target
