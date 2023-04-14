LDLIBS=-lpcap

all: arp-spoof

main.o: mac.h ip.h ethhdr.h arphdr.h arp-spoof.h ipv4hdr.h main.cpp

arp-spoof.o: mac.h ip.h ethhdr.h arphdr.h arp-spoof.h ipv4hdr.h arp-spoof.h arp-spoof.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ipv4hdr.o: ip.h ipv4hdr.h ipv4hdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o arp-spoof.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof-test *.o
