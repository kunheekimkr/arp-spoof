LDLIBS=-lpcap

all: send-arp


main.o: mac.h ip.h ethhdr.h arphdr.h send-arp.h main.cpp

send-arp.o: send-arp.h send-arp.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

send-arp: main.o arphdr.o ethhdr.o ip.o mac.o send-arp.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
