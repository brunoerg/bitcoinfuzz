HEADERS := bitcoin/util/vector.h bitcoin/util/strencodings.h bitcoin/span.h bitcoin/util/spanparsing.h bitcoin/script/script.h compiler.h targets.h bitcoin/script/miniscript.h bitcoin/crypto/common.h bitcoin/serialize.h bitcoin/prevector.h bitcoin/compat/endian.h bitcoin/compat/byteswap.h bitcoin/attributes.h bitcoin/tinyformat.h bitcoin/primitives/transaction.h
SOURCES := bitcoin/util/strencodings.cpp bitcoin/util/spanparsing.cpp bitcoin/script/script.cpp bitcoin/script/miniscript.cpp compiler.cpp targets.cpp

bitcoinfuzz: $(HEADERS) $(SOURCES) fuzzer.cpp
	g++ -O3 -g0 -Wall -fsanitize=address,fuzzer -std=c++17 -march=native -L rust_bitcoin_lib/target/release  -lrust_bitcoin_lib -lpthread -ldl -flto -Ibitcoin $(SOURCES) fuzzer.cpp -o bitcoinfuzz
