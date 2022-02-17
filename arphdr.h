//
// Created by abscom on 6/1/21.
//

#ifndef ARPING_CPP_ARPHDR_H
#define ARPING_CPP_ARPHDR_H

#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
typedef struct arp_hdr {
    uint16_t htype;    /* Hardware Type           */
    uint16_t ptype;    /* Protocol Type           */
    uint8_t hlen;        /* Hardware Address Length */
    uint8_t plen;        /* Protocol Address Length */
    uint16_t oper;     /* Operation Code          */
    uint8_t sha[6];      /* Sender hardware address */
    uint32_t spa;      /* Sender IP address       */
    uint8_t tha[6];      /* Target hardware address */
    uint32_t tpa;      /* Target IP address       */
}__attribute__ ((packed)) arp_hdr_t;
#endif //ARPING_CPP_ARPHDR_H
