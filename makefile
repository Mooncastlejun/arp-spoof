AR = ar
RANLIB = ranlib

# Object files
OBJ_FILES = arp_spoof.o arphdr.o ethhdr.o ip.o mac.o

# Compiler flags
CXXFLAGS = -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -O2 -fsanitize=address,undefined -fsanitize-address-use-after-scope -std=c++11 -I.
LDLIBS = -lpcap
LIB_FUZZING_ENGINE = -fsanitize=fuzzer

all: libarp.a libarp.so example_fuzzer

# Compile individual object files
arp_spoof.o: mac.h ip.h ethhdr.h arphdr.h arp_spoof.cpp
	$(CXX) $(CXXFLAGS) -c arp_spoof.cpp
arphdr.o: mac.h ip.h arphdr.h arphdr.cpp
	$(CXX) $(CXXFLAGS) -c arphdr.cpp
ethhdr.o: mac.h ethhdr.h ethhdr.cpp
	$(CXX) $(CXXFLAGS) -c ethhdr.cpp
ip.o: ip.h ip.cpp
	$(CXX) $(CXXFLAGS) -c ip.cpp
mac.o: mac.h mac.cpp
	$(CXX) $(CXXFLAGS) -c mac.cpp

# Create the fuzzing target
example_fuzzer: $(OBJ_FILES) example_fuzzer.o
	$(CXX) $(CXXFLAGS) example_fuzzer.o $(OBJ_FILES) -o example_fuzzer $(LIB_FUZZING_ENGINE) $(LDLIBS)

# Create the static library (libarp.a)
libarp.a: $(OBJ_FILES)
	$(AR) rcs $@ $^
	$(RANLIB) $@

# Create the dynamic library (libarp.so)
libarp.so: $(OBJ_FILES)
	$(CXX) -shared -o $@ $^

# Cleanup
clean:
	rm -f send-arp-test *.o libarp.a libarp.so example_fuzzer example_fuzzer.o
