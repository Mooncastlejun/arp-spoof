LDLIBS=-lpcap
CXXFLAGS = -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -O2 -fsanitize=address,undefined -fsanitize-address-use-after-scope -g -fPIC
LIB_FUZZING_ENGINE = -fsanitize=fuzzer
AR=ar
RANLIB=ranlib

# Object files
OBJ_FILES = arp_spoof.o arphdr.o ethhdr.o ip.o mac.o

all: send-arp-test libarp.a libarp.so

# 개별 오브젝트 파일 컴파일
arp_spoof.o: mac.h ip.h ethhdr.h arphdr.h arp_spoof.cpp
arphdr.o: mac.h ip.h arphdr.h arphdr.cpp
ethhdr.o: mac.h ethhdr.h ethhdr.cpp
ip.o: ip.h ip.cpp
mac.o : mac.h mac.cpp

# 실행 파일 생성
send-arp-test: arp_spoof.o arphdr.o ethhdr.o ip.o mac.o
	$(CXX) $(CXXFLAGS) arp_spoof.o arphdr.o ethhdr.o ip.o mac.o -lpcap -o send-arp-test $(LIB_FUZZING_ENGINE) ./libarp.a

# 정적 라이브러리(libarp.a) 생성
libarp.a: $(OBJ_FILES)
	$(AR) rcs $@ $^
	$(RANLIB) $@

# 동적 라이브러리(libarp.so) 생성
libarp.so: $(OBJ_FILES)
	$(CXX) -shared -o $@ $^

# 클린업
clean:
	rm -f send-arp-test *.o libarp.a libarp.so