HEADERS :=  $(wildcard $(shell find bitcoin -type f -name '*.h')) compiler.h targets/miniscript_policy.h targets/miniscript_string.h targets/block_des.h
SOURCES :=  $(wildcard $(shell find bitcoin -type f -name '*.cpp')) compiler.cpp targets/miniscript_policy.cpp targets/miniscript_string.cpp targets/block_des.cpp

bitcoinfuzz: $(HEADERS) $(SOURCES) fuzzer.cpp
	clang++ -O3 -g0 -Wall -fsanitize=address,fuzzer -DHAVE_GMTIME_R=1 -std=c++20 -march=native -L rust_bitcoin_lib/target/release  -lrust_bitcoin_lib -lpthread -ldl -flto -Ibitcoin $(SOURCES) fuzzer.cpp -o bitcoinfuzz
