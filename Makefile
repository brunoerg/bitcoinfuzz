HEADERS :=  $(wildcard $(shell find bitcoin -type f -name '*.h')) compiler.h targets/miniscript_policy.h targets/miniscript_string.h 
SOURCES :=  $(wildcard $(shell find bitcoin -type f -name '*.cpp')) compiler.cpp targets/miniscript_policy.cpp targets/miniscript_string.cpp

bitcoinfuzz: $(HEADERS) $(SOURCES) fuzzer.cpp
	g++ -O3 -g0 -Wall -fsanitize=address,fuzzer -std=c++17 -march=native -L rust_bitcoin_lib/target/release  -lrust_bitcoin_lib -lpthread -ldl -flto -Ibitcoin $(SOURCES) fuzzer.cpp -o bitcoinfuzz
