HEADERS :=  $(wildcard $(shell find bitcoin -type f -name '*.h')) compiler.h targets/miniscript_policy.h targets/miniscript_string.h targets/block_des.h targets/prefilledtransaction.h
SOURCES :=  $(wildcard $(shell find bitcoin -type f -name '*.cpp')) compiler.cpp targets/miniscript_policy.cpp targets/miniscript_string.cpp targets/block_des.cpp targets/prefilledtransaction.cpp
UNAME_S :=  $(shell uname -s)

bitcoinfuzz: cargo go $(HEADERS) $(SOURCES) fuzzer.cpp
	clang++ -O3 -g0 -Wall -fsanitize=address,fuzzer -DHAVE_GMTIME_R=1 -std=c++20 -march=native -Wl,-rpath,btcd_lib/,-rpath,rust_bitcoin_lib/target/release -L rust_bitcoin_lib/target/release -L btcd_lib -lbtcd_wrapper -lrust_bitcoin_lib -lpthread -ldl -flto -Ibitcoin $(SOURCES) fuzzer.cpp -o bitcoinfuzz

cargo:
	cd rust_bitcoin_lib && cargo build --release && cd ..

go:
	cd btcd_lib && go build -o libbtcd_wrapper.so -buildmode=c-shared wrapper.go
ifeq ($(UNAME_S),Darwin)
	install_name_tool -id btcd_lib/libbtcd_wrapper.so ./btcd_lib/libbtcd_wrapper.so
endif

clean:
	rm bitcoinfuzz
	rm -Rd rust_bitcoin_lib/target
