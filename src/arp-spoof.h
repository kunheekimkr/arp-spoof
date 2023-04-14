#pragma once

#include <iostream>
#include <cstring>
#include <fstream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <pcap.h>


#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void getAttackerInfo(string interface, Mac& attackerMac, Ip& attackerIP);

void sendARPPacket(pcap_t* handle, Mac& eth_dmac, Mac& eth_smac, Mac& arp_smac, Ip& arp_sip, Mac& arp_tmac, Ip& arp_tip, bool isRequest);

void getMACAddress(pcap_t* handle, Mac& senderMac, Ip& senderIp, Mac& attackerMac, Ip& attackerIp);

void arpSpoof(pcap_t* handle, Mac senderMac, Mac attackerMac, Mac targetMac, Ip targetIp, Ip senderIp);