all: bitcoinfuzz

BASE_CXXFLAGS := -fsanitize=address,fuzzer -Wall -Wextra -std=c++20 -I include -I .
UNAME_S := $(shell uname -s)
BITCOINFUZZ_SRC := basemodule modulelogger
BITCOINFUZZ_OBJS := $(addprefix include/bitcoinfuzz/, $(addsuffix .o, $(BITCOINFUZZ_SRC)))
HELPERS_SRC := jvmloader
HELPERS_OBJS := $(addprefix helpers/, $(addsuffix .o, $(HELPERS_SRC)))

BITCOINFUZZ_DIR = $(shell pwd)
CXXFLAGS += -DBITCOINFUZZ_DIR=\"$(BITCOINFUZZ_DIR)\"

# Conditionally include module.a files based on compilation flags
MODULES :=
ifneq ($(findstring -DBITCOIN_CORE,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/bitcoin/module.a
endif

ifneq ($(findstring -DRUST_PSBT,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/rustpsbt/module.a
endif

ifneq ($(findstring -DRUST_BITCOIN,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/rustbitcoin/module.a
endif

ifneq ($(findstring -DRUST_MINISCRIPT,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/rustminiscript/module.a
endif

ifneq ($(findstring -DTINY_MINISCRIPT,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/tinyminiscript/module.a
endif

ifneq ($(findstring -DBITCOINERLAB_MINISCRIPT,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/bitcoinerlabminiscript/module.a
endif

ifneq ($(findstring -DBTCD,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/btcd/module.a
endif

ifneq ($(findstring -DGOCOIN,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/gocoin/module.a
endif

ifneq ($(filter -DNBITCOIN,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/nbitcoin/module.a
endif

ifneq ($(findstring -DLND,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/lnd/module.a
endif

ifneq ($(findstring -DLDK,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/ldk/module.a
endif

ifneq ($(findstring -DECLAIR,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/eclair/module.a
endif

ifneq ($(findstring -DNLIGHTNING,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/nlightning/module.a
endif

ifneq ($(findstring -DEMBIT,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/embit/module.a
endif

ifneq ($(findstring -DPYBITCOINKERNEL,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/pybitcoinkernel/module.a
endif

ifneq ($(findstring -DRUSTBITCOINKERNEL,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/rustbitcoinkernel/module.a
endif

ifneq ($(findstring -DCLIGHTNING,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	SODIUM_LDLIBS = $(shell pkg-config --silence-errors --libs libsodium 2>/dev/null)
	MODULES += modules/clightning/module.a
endif

ifneq ($(findstring -DLIGHTNING_KMP,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/lightningkmp/module.a
endif

ifneq ($(findstring -DBITCOINJ,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/bitcoinj/module.a
endif

ifneq ($(findstring -DBITCOINS,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/bitcoins/module.a
endif

# Add custom mutator module
ifneq (,$(filter -DCUSTOM_MUTATOR%,$(BASE_CXXFLAGS) $(CXXFLAGS)))
	MODULES += custommutator/module.a
endif

ifneq ($(findstring -DDECRED_SECP256K1,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/decredsecp256k1/module.a
endif

ifneq ($(findstring -DSECP256K1,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/secp256k1/module.a
endif

ifneq ($(filter -DNBITCOIN_SECP256K1,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/nbitcoinsecp256k1/module.a
endif

ifneq ($(findstring -DRUST_K256,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/rustk256/module.a
endif

ifneq ($(findstring -DLIBWALLY_CORE,$(BASE_CXXFLAGS) $(CXXFLAGS)),)                                                                                                                                   
  MODULES += modules/libwallycore/module.a                                                                                                                                                           
endif   

ifneq ($(filter -DBITCOINKERNEL,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/bitcoinkernel/module.a
endif

ifneq ($(filter -DBITCOINKERNEL_VARIANT,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/bitcoinkernelvariant/module.a
endif

ifneq ($(findstring -DPYCOIN,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/pycoin/module.a
endif

ifneq ($(findstring -DRUST_MUSIG2,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/rustmusig2/module.a
endif

ifneq ($(findstring -DRUSTCRYPTO_AES,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/rustcryptoaes/module.a
endif

ifneq ($(findstring -DBOOST_MULTI_INDEX,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/boostmultiindex/module.a
endif

ifneq ($(findstring -DTMI2,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/tmi2/module.a
endif

ifeq ($(UNAME_S), Darwin)
	LDFLAGS = -framework CoreFoundation -Wl,-ld_classic
endif

ifeq ($(UNAME_S), Darwin)
	LIB_EXT := dylib
else
	LIB_EXT := so
endif

ifneq ($(filter -DNBITCOIN,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
  NBITCOIN_LIB := ./NBitcoin.CppBridge.$(LIB_EXT)
endif

ifneq ($(findstring -DNLIGHTNING,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
  NLIGHTNING_LIB := ./NLightning.CppBridge.$(LIB_EXT)
endif

ifneq ($(filter -DNBITCOIN_SECP256K1,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
  NBITCOIN_SECP256K1_LIB := ./NBitcoinSecp256k1.CppBridge.$(LIB_EXT)
endif

ifneq ($(findstring -DTINY_MINISCRIPT,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
  TINY_MINISCRIPT_LIB := ./libtiny_miniscript_lib.$(LIB_EXT)
endif

# Check for EMBIT define and add Python-related flags
ifneq ($(findstring -DEMBIT,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
  PYTHON_LDFLAGS := $(shell python3-config --ldflags --embed)
endif

ifneq ($(findstring -DPYBITCOINKERNEL,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
  PYTHON_LDFLAGS := $(shell python3-config --ldflags --embed)
endif

ifneq ($(findstring -DPYCOIN,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
  PYTHON_LDFLAGS := $(shell python3-config --ldflags --embed)
endif

# Check that the Java modules are defined to add Java-related flags.
ifneq (,$(filter -DECLAIR -DLIGHTNING_KMP -DBITCOINJ -DBITCOINS,$(BASE_CXXFLAGS) $(CXXFLAGS)))
	ifeq ($(UNAME_S), Darwin)
		JAVA_HOME ?= $(shell /usr/libexec/java_home)
	else
		JAVA_HOME ?= $(shell dirname $$(dirname $$(readlink -f $$(which javac))))
	endif

  JAVA_CXXFLAGS := -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/$(shell uname -s | tr '[:upper:]' '[:lower:]') -L$(JAVA_HOME)/lib/server -ljvm -Wl,-rpath,$(JAVA_HOME)/lib/server
	JVM_LOADER := helpers/jvmloader.o
endif

ifneq ($(findstring -DRUSTREEXO,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/rustreexo/module.a
endif

ifneq ($(findstring -DUTREEXO,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/utreexo/module.a
endif

ifneq ($(findstring -DLIBBITCOIN_SYSTEM,$(BASE_CXXFLAGS) $(CXXFLAGS)),)
	MODULES += modules/libbitcoinsystem/module.a
	BOOST_ROOT ?= /usr
	LIBBITCOIN_CXXFLAGS := -I$(BOOST_ROOT)/include
	LIBBITCOIN_LDLIBS   := -L$(BOOST_ROOT)/lib -lboost_program_options
endif

CXXFLAGS := $(BASE_CXXFLAGS) $(JAVA_CXXFLAGS) $(CXXFLAGS) $(PYTHON_LDFLAGS) $(LIBBITCOIN_CXXFLAGS)

bitcoinfuzz: main.cpp driver.o $(BITCOINFUZZ_OBJS) $(JVM_LOADER)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) main.cpp driver.o $(BITCOINFUZZ_OBJS) $(JVM_LOADER) $(MODULES) $(NBITCOIN_LIB) $(NLIGHTNING_LIB) $(NBITCOIN_SECP256K1_LIB) $(TINY_MINISCRIPT_LIB) -o bitcoinfuzz $(PYTHON_LDFLAGS) $(SODIUM_LDLIBS) $(LIBBITCOIN_LDLIBS)

driver.o: driver.cpp driver.h
	$(CXX) $(CXXFLAGS) -c driver.cpp -o driver.o

include/bitcoinfuzz/%.o: include/bitcoinfuzz/%.cpp include/bitcoinfuzz/%.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

helpers/%.o: helpers/%.cpp helpers/%.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

format:
	clang-format -i include/bitcoinfuzz/*.h include/bitcoinfuzz/*.cpp driver.cpp driver.h main.cpp helpers/*.cpp helpers/*.h

format-all: format
	$(MAKE) -C custommutator format
	@for dir in modules/*/; do $(MAKE) -C $$dir format; done

check-format:
	clang-format -Werror --fail-on-incomplete-format -n include/bitcoinfuzz/*.h include/bitcoinfuzz/*.cpp driver.cpp driver.h main.cpp helpers/*.cpp helpers/*.h

check-format-all:
	@EXIT_CODE=0; \
	$(MAKE) check-format || EXIT_CODE=1; \
	$(MAKE) -C custommutator check-format || EXIT_CODE=1; \
	for dir in modules/*/; do \
		$(MAKE) -C $$dir check-format || EXIT_CODE=1; \
	done; \
	exit $$EXIT_CODE

clean:
	rm -rf *.o module.a bitcoinfuzz include/bitcoinfuzz/*.o helpers/*.o $(MODULES)
	rm -rf modules/eclair/eclair.zip modules/eclair/lib modules/eclair/eclair_extracted


.PHONY: all bitcoinfuzz
