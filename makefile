LDLIBS=-lpcap
LIBARPSRC=arp.cpp  # 라이브러리 소스 파일 추가
LIBARPDIR=libarp.a  # 생성할 정적 라이브러리 이름
LIBARPDYN=libarp.so  # 생성할 동적 라이브러리 이름

all: send-arp-test $(LIBARPDIR) $(LIBARPDYN)

# 객체 파일
main.o: mac.h ip.h ethhdr.h arphdr.h main.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp
	$(CXX) $(CXXFLAGS) -c arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp
	$(CXX) $(CXXFLAGS) -c ethhdr.cpp

ip.o: ip.h ip.cpp
	$(CXX) $(CXXFLAGS) -c ip.cpp

mac.o : mac.h mac.cpp
	$(CXX) $(CXXFLAGS) -c mac.cpp

# 정적 라이브러리 빌드
$(LIBARPDIR): mac.o ip.o arphdr.o ethhdr.o
	$(AR) rcs $@ $^

# 동적 라이브러리 빌드
$(LIBARPDYN): mac.o ip.o arphdr.o ethhdr.o
	$(CXX) -shared -o $@ $^

# 실행 파일 빌드
send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o $(LIBARPDIR) $(LIBARPDYN)
