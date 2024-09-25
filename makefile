LDLIBS = -lpcap
CXXFLAGS = -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -O2 -fsanitize=address,undefined -fsanitize-address-use-after-scope -g -std=c++11 -I. /prompt_fuzz/output/build/arp-spoof/src/arp-spoof/example_fuzzer.cpp -o /example_fuzzer -fsanitize=fuzzer ./libarp.a -lpcap -fPIC
LIB_FUZZING_ENGINE = -fsanitize=fuzzer
AR = ar
RANLIB = ranlib

# Object files
OBJ_FILES = arp_spoof.o arphdr.o ethhdr.o ip.o mac.o

all: libarp.a libarp.so example_fuzzer

# 개별 오브젝트 파일 컴파일
arp_spoof.o: mac.h ip.h ethhdr.h arphdr.h arp_spoof.cpp
	$(CXX) $(CXXFLAGS) -c arp_spoof.cpp
arphdr.o: mac.h ip.h arphdr.h arphdr.cpp
	$(CXX) $(CXXFLAGS) -c arphdr.cpp
ethhdr.o: mac.h ethhdr.h ethhdr.cpp
	$(CXX) $(CXXFLAGS) -c ethhdr.cpp
ip.o: ip.h ip.cpp
	$(CXX) $(CXXFLAGS) -c ip.cpp
mac.o : mac.h mac.cpp
	$(CXX) $(CXXFLAGS) -c mac.cpp

# Fuzzing 타겟 생성
example_fuzzer: $(OBJ_FILES) example_fuzzer.o
	$(CXX) $(CXXFLAGS) -std=c++11 example_fuzzer.cpp -o example_fuzzer $(LIB_FUZZING_ENGINE) ./libarp.a

# 정적 라이브러리(libarp.a) 생성
libarp.a: $(OBJ_FILES)
	$(AR) rcs $@ $^
	$(RANLIB) $@

# 동적 라이브러리(libarp.so) 생성
libarp.so: $(OBJ_FILES)
	$(CXX) -shared -o $@ $^

# 클린업
clean:
	rm -f send-arp-test *.o libarp.a libarp.so example_fuzzer example_fuzzer.o
