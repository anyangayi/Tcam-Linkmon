//
// Created by abscom on 6/1/21.
//

#ifndef ARPING_CPP_LINKINFO_H
#define ARPING_CPP_LINKINFO_H

#include <atomic>
#include <net/ethernet.h>
#ifdef DEBUG
#define debug(format, ...)  fprintf(stderr, format, ##__VA_ARGS__)
#else
#define debug(format, ...)
#endif

class LinkInfo {
    struct arphdr
          {
            unsigned short int ar_hrd;      /* Format of hardware address.  */
            unsigned short int ar_pro;      /* Format of protocol address.  */
            unsigned char ar_hln;       /* Length of hardware address.  */
            unsigned char ar_pln;       /* Length of protocol address.  */
            unsigned short int ar_op;       /* ARP opcode (command).  */
          };
        struct  ether_arp {
            struct  arphdr ea_hdr;      /* fixed-size header */
            uint8_t arp_sha[ETH_ALEN];  /* sender hardware address */
            uint8_t arp_spa[4];     /* sender protocol address */
            uint8_t arp_tha[ETH_ALEN];  /* target hardware address */
            uint8_t arp_tpa[4];     /* target protocol address */
        };

    typedef struct arp_packet {
        struct ether_header eh;
        struct ether_arp arp;
    } ArpPacket;
    typedef struct {
        uint8_t data[ETH_ALEN];
    } mac_addr;

    in_addr_t toIp ;
    mac_addr fromMac;
    in_addr_t fromIp;
    mac_addr toMac;
    int socketFd = 0;
    int interfIndex;

    static in_addr_t getInterfaceIp(const char *interfaceName);

    static mac_addr getInterfaceMac(const char *interfaceName);

    static int getInterfaceIndex(const char *interfaceName);

    static time_t getTimeStamp();



public:
    std::string targetIp;
    std::string sourceIfaceName;
    int portIndex, tcamIndex;
    std::atomic<uint64_t> lastUpdate;
    int latestStatus;  //保存上一次的状态

    LinkInfo(std::string targetIp, int portIndex, int tcamIndex, std::string sourceIfaceName);

    void update();

    int sendARPRequest() const;

    uint64_t checkTimeout();

    LinkInfo(const LinkInfo &other) : targetIp(other.targetIp), sourceIfaceName(other.sourceIfaceName),
                                      portIndex(other.portIndex),
                                      tcamIndex(other.tcamIndex),
                                      lastUpdate((uint64_t) other.lastUpdate),
                                      toIp(other.toIp),
                                      toMac(other.toMac),
                                      fromIp(other.fromIp),
                                      fromMac(other.fromMac),
                                      socketFd(other.socketFd),
                                      interfIndex(other.interfIndex),
                                      latestStatus(other.latestStatus)
                                      {}



};

#endif //ARPING_CPP_LINKINFO_H
