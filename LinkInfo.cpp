//
// Created by abscom on 6/1/21.
//

#ifndef ARPING_CPP_LINKINFO_CPP
#define ARPING_CPP_LINKINFO_CPP

#include <iostream>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <thread>
#include "arphdr.h"
#include "LinkInfo.h"


std::time_t LinkInfo::getTimeStamp() {
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp = std::chrono::time_point_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    std::time_t timestamp = tmp.count();
    return timestamp;
}

void LinkInfo::update() {
    lastUpdate = getTimeStamp();
}

int LinkInfo::sendARPRequest() const {

    // Construct an ARP Request
    ArpPacket arpPacket;
    arpPacket.eh.ether_type = htons(ETHERTYPE_ARP);
    memcpy(arpPacket.eh.ether_dhost, toMac.data, ETH_ALEN);
    memcpy(arpPacket.eh.ether_shost, fromMac.data, ETH_ALEN);
    arpPacket.arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arpPacket.arp.ea_hdr.ar_pro = htons(ETH_P_IP);
    arpPacket.arp.ea_hdr.ar_hln = ETH_ALEN;
    arpPacket.arp.ea_hdr.ar_pln = 4;
    arpPacket.arp.ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(arpPacket.arp.arp_sha, fromMac.data, ETH_ALEN);
    memcpy(arpPacket.arp.arp_spa, &fromIp, 4);
    memcpy(arpPacket.arp.arp_tha, toMac.data, ETH_ALEN);
    memcpy(arpPacket.arp.arp_tpa, &toIp, 4);

    // Get interface index, as it may changed by the hot-plug feature.
    struct sockaddr_ll dest = {0};
    if (interfIndex < 0) {
        debug("get interface index error\n");
        return -1;
    }
#ifdef SYLIXOS
    dest.sll_hatype = ARPHRD_ETHER; // Patch for SylixOS, as type check procedure required @af_packet.c:1463
#endif
    dest.sll_family = AF_PACKET;
    dest.sll_ifindex = interfIndex;

    // Send to target net-device
    int err = sendto(socketFd, &arpPacket, sizeof(ArpPacket), 0, (struct sockaddr *) &dest, sizeof(dest));
    if (err < sizeof(arpPacket)) {
#ifdef DEBUG
        perror(__FUNCTION__ );
#endif
        debug("sendto data error, errno: %d, errstr: %s\n", errno, strerror(errno));
    } else {
        debug("send data success\n");
    }
    return 0;
}

int LinkInfo::getInterfaceIndex(const char *interfaceName) {
    struct ifreq req{};
    int skfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_RARP));
    strcpy(req.ifr_name, interfaceName);
    if (ioctl(skfd, SIOCGIFINDEX, &req) < 0) {
        debug("ioctl error, errno: %d, errmsg: %s\n", errno, strerror(errno));
        return -1;
    }
    return req.ifr_ifindex;
}

LinkInfo::mac_addr LinkInfo::getInterfaceMac(const char *interfaceName) {
    int skfd = 0;
    struct ifreq ifr{};
    mac_addr addr;
    uint8_t *mac = &(addr.data[0]);

    skfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(ifr.ifr_name, interfaceName);
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
        debug("ioctl error, errno: %d, errnostr: %s\n", errno, strerror(errno));
        return addr;
    }
    close(skfd);

    mac[0] = (unsigned char) ifr.ifr_hwaddr.sa_data[0];
    mac[1] = (unsigned char) ifr.ifr_hwaddr.sa_data[1];
    mac[2] = (unsigned char) ifr.ifr_hwaddr.sa_data[2];
    mac[3] = (unsigned char) ifr.ifr_hwaddr.sa_data[3];
    mac[4] = (unsigned char) ifr.ifr_hwaddr.sa_data[4];
    mac[5] = (unsigned char) ifr.ifr_hwaddr.sa_data[5];
    return addr;
}


LinkInfo::LinkInfo(std::string targetIp, int portIndex, int tcamIndex, std::string sourceIfaceName) : targetIp(
        targetIp), sourceIfaceName(sourceIfaceName), portIndex(portIndex), tcamIndex(tcamIndex), latestStatus(-1) {
    toIp = inet_addr(targetIp.c_str());
    ::memset(&toMac.data,0xff,6);
    fromMac = getInterfaceMac(sourceIfaceName.c_str());
    fromIp = getInterfaceIp(sourceIfaceName.c_str());
    interfIndex= getInterfaceIndex(sourceIfaceName.c_str());
    lastUpdate = getTimeStamp();
    socketFd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

}

in_addr_t LinkInfo::getInterfaceIp(const char *interfaceName) {
    struct ifreq ifr{};
    int skfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(ifr.ifr_name, interfaceName);
    if (ioctl(skfd, SIOCGIFADDR, &ifr) < 0) {
        debug("ioctl error, errno: %d, errnostr: %s\n", errno, strerror(errno));
    }
    close(skfd);
    struct in_addr addr = ((struct sockaddr_in *) (&ifr.ifr_addr))->sin_addr;
    return addr.s_addr;
}

uint64_t LinkInfo::checkTimeout() {
    return getTimeStamp() - lastUpdate;
}


#endif //ARPING_CPP_LINKINFO_CPP
