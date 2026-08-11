all: module.a

SYMBOL_PREFIX ?= bitcoin_core

# Detect objcopy command
OBJCOPY := $(shell command -v objcopy 2> /dev/null)
ifeq ($(OBJCOPY),)
$(error objcopy not found. Install with: apt-get install binutils)
endif

BITCOIN_SRC = ../../external/bitcoin-core/src
SECP256K1_DIR = $(BITCOIN_SRC)/secp256k1
UNIVALUE_DIR = $(BITCOIN_SRC)/univalue
LEVELDB_DIR = $(BITCOIN_SRC)/leveldb

CXXFLAGS += -Wall -Wextra -std=c++20 \
            -fsanitize=fuzzer,address \
            -I . \
            -I $(BITCOIN_SRC) \
            -I ../../include \
            -I $(SECP256K1_DIR)/include \
            -I $(UNIVALUE_DIR)/include \
            -I $(BITCOIN_SRC)/consensus \
            -I $(BITCOIN_SRC)/primitives \
            -I $(BITCOIN_SRC)/script \
            -I $(LEVELDB_DIR)/include \
            -I $(LEVELDB_DIR)

SECP256K1_LIB = $(SECP256K1_DIR)/.libs/libsecp256k1.a
UNIVALUE_LIB = build/univalue/libunivalue.a
LEVELDB_LIB = build/leveldb/libleveldb.a
MAKE = make

# Explicit list of Bitcoin Core source files needed (relative to BITCOIN_SRC)
BITCOIN_SRCS := \
    addresstype.cpp \
    arith_uint256.cpp \
    base58.cpp \
    bech32.cpp \
    blockencodings.cpp \
    blockfilter.cpp \
    chain.cpp \
    chainparamsbase.cpp \
    chainparams.cpp \
    coins.cpp \
    common/args.cpp \
    common/bloom.cpp \
    common/config.cpp \
    common/init.cpp \
    common/messages.cpp \
    common/settings.cpp \
    common/signmessage.cpp \
    common/system.cpp \
    common/url.cpp \
    compat/stdin.cpp \
    compressor.cpp \
    consensus/merkle.cpp \
    consensus/tx_check.cpp \
    core_io.cpp \
    crypto/aes.cpp \
    crypto/chacha20.cpp \
    crypto/chacha20poly1305.cpp \
    crypto/hex_base.cpp \
    crypto/hkdf_sha256_32.cpp \
    crypto/hmac_sha256.cpp \
    crypto/hmac_sha512.cpp \
    crypto/muhash.cpp \
    crypto/poly1305.cpp \
    crypto/ripemd160.cpp \
    crypto/sha1.cpp \
    crypto/sha256_arm_shani.cpp \
    crypto/sha256_avx2.cpp \
    crypto/sha256.cpp \
    crypto/sha256_sse41.cpp \
    crypto/sha256_sse4.cpp \
    crypto/sha256_x86_shani.cpp \
    crypto/sha3.cpp \
    crypto/sha512.cpp \
    crypto/siphash.cpp \
    flatfile.cpp \
    hash.cpp \
    kernel/chainparams.cpp \
    kernel/cs_main.cpp \
    key.cpp \
    key_io.cpp \
    logging.cpp \
    merkleblock.cpp \
    musig.cpp \
    netaddress.cpp \
    outputtype.cpp \
    policy/feerate.cpp \
    policy/fees/block_policy_estimator.cpp \
    policy/fees/block_policy_estimator_args.cpp \
    policy/policy.cpp \
    primitives/block.cpp \
    primitives/transaction.cpp \
    protocol.cpp \
    psbt.cpp \
    pubkey.cpp \
    random.cpp \
    randomenv.cpp \
    script/descriptor.cpp \
    script/interpreter.cpp \
    script/miniscript.cpp \
    script/parsing.cpp \
    script/script.cpp \
    script/script_error.cpp \
    script/sigcache.cpp \
    script/sign.cpp \
    script/signingprovider.cpp \
    script/solver.cpp \
    streams.cpp \
    support/lockedpool.cpp \
    sync.cpp \
    uint256.cpp \
    util/batchpriority.cpp \
    util/bip32.cpp \
    util/bytevectorhash.cpp \
    util/chaintype.cpp \
    util/check.cpp \
    util/exception.cpp \
    util/feefrac.cpp \
    util/fs.cpp \
    util/fs_helpers.cpp \
    util/hasher.cpp \
    util/moneystr.cpp \
    util/rbf.cpp \
    util/readwritefile.cpp \
    util/serfloat.cpp \
    util/strencodings.cpp \
    util/string.cpp \
    util/syserror.cpp \
    util/thread.cpp \
    util/threadinterrupt.cpp \
    util/threadnames.cpp \
    util/time.cpp \
    util/tokenpipe.cpp \
    util/signalinterrupt.cpp \
    validation.cpp \
    validationinterface.cpp \
    versionbits.cpp \
    clientversion.cpp \
    consensus/tx_verify.cpp \
    deploymentinfo.cpp \
    kernel/chain.cpp \
    kernel/mempool_removal_reason.cpp \
    dbwrapper.cpp \
    kernel/coinstats.cpp \
    kernel/disconnected_transactions.cpp \
    node/blockstorage.cpp \
    node/chainstate.cpp \
    node/utxo_snapshot.cpp \
    policy/ephemeral_policy.cpp \
    policy/packages.cpp \
    policy/rbf.cpp \
    policy/settings.cpp \
    policy/truc_policy.cpp \
    pow.cpp \
    signet.cpp \
    txdb.cpp \
    txgraph.cpp \
    txmempool.cpp

BITCOIN_FULL_SRCS := $(addprefix $(BITCOIN_SRC)/, $(BITCOIN_SRCS))
BITCOIN_OBJS := $(addprefix build/, $(BITCOIN_SRCS:.cpp=.o))

# Build libsecp256k1 with sanitizer flags
$(SECP256K1_LIB):
	@echo "Building secp256k1..."
	cd $(SECP256K1_DIR) && set -e && \
	./autogen.sh && \
	./configure \
		--enable-module-recovery \
		--enable-experimental \
		--enable-module-schnorrsig \
		--enable-module-musig \
		--disable-shared \
		--with-pic \
		CFLAGS="-fsanitize=address,fuzzer-no-link" && \
	$(MAKE)
	@test -f $(SECP256K1_LIB) || { echo "ERROR: $(SECP256K1_LIB) not created"; exit 1; }

# Build univalue directly (its CMakeLists.txt is not standalone)
UNIVALUE_SRCS := univalue.cpp univalue_get.cpp univalue_read.cpp univalue_write.cpp
UNIVALUE_OBJS := $(addprefix build/univalue/, $(UNIVALUE_SRCS:.cpp=.o))

build/univalue/%.o: $(UNIVALUE_DIR)/lib/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) -std=c++20 -fPIC -fsanitize=fuzzer-no-link -I$(UNIVALUE_DIR)/include -c $< -o $@

$(UNIVALUE_LIB): $(UNIVALUE_OBJS)
	@echo "Building univalue..."
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $(UNIVALUE_OBJS)

# Build LevelDB
LEVELDB_SRCS := \
    db/builder.cc \
    db/db_impl.cc \
    db/db_iter.cc \
    db/dbformat.cc \
    db/dumpfile.cc \
    db/filename.cc \
    db/log_reader.cc \
    db/log_writer.cc \
    db/memtable.cc \
    db/repair.cc \
    db/table_cache.cc \
    db/version_edit.cc \
    db/version_set.cc \
    db/write_batch.cc \
    helpers/memenv/memenv.cc \
    table/block.cc \
    table/block_builder.cc \
    table/filter_block.cc \
    table/format.cc \
    table/iterator.cc \
    table/merger.cc \
    table/table.cc \
    table/table_builder.cc \
    table/two_level_iterator.cc \
    util/arena.cc \
    util/bloom.cc \
    util/cache.cc \
    util/coding.cc \
    util/comparator.cc \
    util/crc32c.cc \
    util/env.cc \
    util/env_posix.cc \
    util/filter_policy.cc \
    util/hash.cc \
    util/histogram.cc \
    util/logging.cc \
    util/options.cc \
    util/status.cc

LEVELDB_OBJS := $(addprefix build/leveldb/, $(LEVELDB_SRCS:.cc=.o))

LEVELDB_PORT_CONFIG = build/leveldb/port/port_config.h

LEVELDB_CXXFLAGS = -std=c++17 -fPIC \
    -DLEVELDB_PLATFORM_POSIX \
    -DHAVE_FDATASYNC=1 \
    -DHAVE_O_CLOEXEC=1 \
    -DHAVE_CRC32C=0 \
    -DHAVE_SNAPPY=0 \
    -DHAVE_FULLFSYNC=0 \
    -I$(LEVELDB_DIR) \
    -I$(LEVELDB_DIR)/include

$(LEVELDB_PORT_CONFIG):
	@mkdir -p $(dir $@)
	@printf '#ifndef STORAGE_LEVELDB_PORT_PORT_CONFIG_H_\n' > $@
	@printf '#define STORAGE_LEVELDB_PORT_PORT_CONFIG_H_\n' >> $@
	@printf '#define HAVE_FDATASYNC 1\n' >> $@
	@printf '#define HAVE_FULLFSYNC 0\n' >> $@
	@printf '#define HAVE_O_CLOEXEC 1\n' >> $@
	@printf '#define HAVE_CRC32C 0\n' >> $@
	@printf '#define HAVE_SNAPPY 0\n' >> $@
	@printf '#endif\n' >> $@

build/leveldb/%.o: $(LEVELDB_DIR)/%.cc $(LEVELDB_PORT_CONFIG)
	@mkdir -p $(dir $@)
	$(CXX) $(LEVELDB_CXXFLAGS) -Ibuild/leveldb -c $< -o $@

$(LEVELDB_LIB): $(LEVELDB_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $(LEVELDB_OBJS)

# Generate symbol redefine map: prefix every global symbol defined in
# libsecp256k1.a (not just secp256k1_*) so they don't collide with the
# standalone secp256k1 module when both are linked together. This catches the
# `__odr_asan_gen_*` ODR-detection symbols that ASAN auto-generates, which
# would otherwise produce multiple-definition errors at the final link.
# Same pattern as modules/libbitcoinsystem/Makefile.
secp256k1_symbols.map: $(SECP256K1_LIB)
	@echo "Generating comprehensive symbol map..."
	@{ \
		nm -g --defined-only $(SECP256K1_LIB) | awk '{print $$3}'; \
		nm --defined-only $(SECP256K1_LIB) | awk '$$2 == "n" {print $$3}'; \
	} | grep -Ev '^$$' | sort -u | while read sym; do \
		echo "$$sym $(SYMBOL_PREFIX)_$$sym"; \
	done > $@
	@sort -u -o $@ $@
	@echo "Generated $$(wc -l < $@) symbol mappings"

.PHONY: compile_objects
compile_objects: module.o cleanse.o $(BITCOIN_OBJS)

module.a: $(SECP256K1_LIB) $(UNIVALUE_LIB) $(LEVELDB_LIB) secp256k1_symbols.map compile_objects
	@echo "========================================"
	@echo "Building module.a with symbol prefix: $(SYMBOL_PREFIX)"
	@echo "========================================"

	# Now rename symbols in all compiled object files
	@echo "Renaming secp256k1 symbols in Bitcoin object files..."
	@for obj in module.o cleanse.o $(BITCOIN_OBJS); do \
		if [ -f "$$obj" ]; then \
			echo "  Renaming symbols in $$obj..."; \
			$(OBJCOPY) --redefine-syms=secp256k1_symbols.map $$obj; \
		fi \
	done

	@echo "Verifying renamed symbols in build/pubkey.o:"
	@nm build/pubkey.o | grep secp256k1 | head -3

	# Create archive with renamed Bitcoin objects
	@echo "Creating archive with renamed objects..."
	$(AR) rcs $@ module.o cleanse.o $(BITCOIN_OBJS)

	mkdir -p tmp_obj
	# Extract secp256k1 objects and rename symbols using the same
	# comprehensive map applied to the Bitcoin objects above, so every
	# defined symbol (including ASAN's __odr_asan_gen_* ODR-detection
	# globals) is prefixed and can't collide with the standalone
	# secp256k1 module.
	cd tmp_obj && $(AR) x ../$(SECP256K1_LIB)
	@echo "Renaming secp256k1 symbols (including ASAN ODR globals)..."
	cd tmp_obj && for obj in *.o; do \
		$(OBJCOPY) --redefine-syms=../secp256k1_symbols.map $$obj; \
	done
	$(AR) rcs $@ tmp_obj/*.o
	rm -rf tmp_obj/*

	# Extract and add univalue WITHOUT prefixing (no conflicts)
	cd tmp_obj && $(AR) x ../$(UNIVALUE_LIB)
	@echo "Adding univalue symbols (no renaming needed)..."
	$(AR) rcs $@ tmp_obj/*.o
	rm -rf tmp_obj

	# Extract and add leveldb, prefixing filenames to avoid basename conflicts
	# (leveldb has logging.o, hash.o, bloom.o which clash with Bitcoin's members)
	mkdir -p tmp_obj
	cd tmp_obj && $(AR) x ../$(LEVELDB_LIB)
	@echo "Prefixing leveldb object names to avoid archive member conflicts..."
	@for obj in tmp_obj/*.o; do \
		mv "$$obj" "tmp_obj/ldb_$$(basename $$obj)"; \
	done
	@echo "Adding leveldb symbols (no renaming needed)..."
	$(AR) rcs $@ tmp_obj/ldb_*.o
	rm -rf tmp_obj
	@echo "Regenerating archive symbol table..."
	ranlib $@
	@echo ""
	@echo "✓ module.a built successfully with prefix: $(SYMBOL_PREFIX)"

module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -I . -fPIC -c module.cpp -o module.o

cleanse.o: $(BITCOIN_SRC)/support/cleanse.cpp
	$(CXX) $(CXXFLAGS) -fPIC -c $< -o cleanse.o

build/%.o: $(BITCOIN_SRC)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -fPIC -c $< -o $@

clean:
	rm -rf *.o build/ module.a tmp_obj/ secp256k1_symbols.map
	cd $(SECP256K1_DIR) && $(MAKE) clean || true
	rm -rf build/univalue || true

format:
	clang-format -i ./module.cpp ./module.h

check-format:
	clang-format -Werror --fail-on-incomplete-format -n ./module.cpp ./module.h

.PHONY: clean all format check-format compile_objects
