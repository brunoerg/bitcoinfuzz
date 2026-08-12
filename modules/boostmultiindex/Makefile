all: module.a

MULTI_INDEX_DIR = ../../external/multi_index
MP11_DIR = ../../external/boost-mp11

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Darwin)
  BOOST_ROOT ?= $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
else
  BOOST_ROOT ?= /usr
endif

# The pinned multi_index and mp11 checkouts must precede system Boost so their
# headers shadow the system copies; system Boost only supplies the remaining
# support headers. mp11 is pinned too because multi_index master requires a
# newer mp11 than most system Boost packages ship.
CXXFLAGS += -Wall -Wextra -std=c++20 -fsanitize=address,fuzzer-no-link \
            -I . -I ../../include \
            -I $(MULTI_INDEX_DIR)/include \
            -I $(MP11_DIR)/include \
            -isystem $(BOOST_ROOT)/include

module.a: module.o
	ar rcs module.a module.o

module.o: module.cpp module.h ../../include/bitcoinfuzz/multiindex_harness.h \
	../../include/bitcoinfuzz/singleindex_harness.h
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o

format:
	clang-format -i ./module.cpp ./module.h

check-format:
	clang-format -Werror --fail-on-incomplete-format -n ./module.cpp ./module.h

clean:
	rm -rf *.o module.a

.PHONY: all clean format check-format
