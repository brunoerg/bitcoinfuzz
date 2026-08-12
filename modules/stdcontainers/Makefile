all: module.a

CXXFLAGS += -Wall -Wextra -std=c++20 -fsanitize=address,fuzzer-no-link \
            -I . -I ../../include

module.a: module.o
	ar rcs module.a module.o

module.o: module.cpp module.h ../../include/bitcoinfuzz/singleindex_harness.h
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o

format:
	clang-format -i ./module.cpp ./module.h

check-format:
	clang-format -Werror --fail-on-incomplete-format -n ./module.cpp ./module.h

clean:
	rm -rf *.o module.a

.PHONY: all clean format check-format
