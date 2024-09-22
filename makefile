LDLIBS=-lpcap
AR=ar
RANLIB=ranlib

# Object files
OBJ_FILES = main.o arphdr.o ethhdr.o ip.o mac.o

all: send-arp-test libarp.a libarp.so

# 개별 오브젝트 파일 컴파일
main.o: mac.h ip.h ethhdr.h arphdr.h main.cpp
arphdr.o: mac.h ip.h arphdr.h arphdr.cpp
ethhdr.o: mac.h ethhdr.h ethhdr.cpp
ip.o: ip.h ip.cpp
mac.o : mac.h mac.cpp

# 실행 파일 생성
send-arp-test: $(OBJ_FILES)
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

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