#include <SylixOS.h> //所有c++项目必须第一个引入此文件
#include <iostream>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <thread>
#include <pcap.h>
#include <csignal>
#include "inicpp.h"
#include "LinkInfo.h"
#include "arphdr.h"
#include "httplib.h" // 一定使用C++11标准,并开启异常支持

//#define DEBUG

#define TIMEOUT_MS 2000  //2000->20->200->500
#define TASK_SEND_ARP_REQ_INTERVAL_MS 1000  //1000->10->100
#define TASK_AGING_CHECK_INTERVAL_MS 1000  //1000->30->100

#define ADDR "127.0.0.1"
#define PORT 8081
#define PATH "/writeTCAM"
#define DATA_TMPL "secure=1&"\
              "retry=9&"\
              "index=%d&"\
              "status=%d&"\
              "sip=192.168.1.100&"\
              "sip_mask=255.255.255.255&"\
              "dip=192.168.2.100&"\
              "dip_mask=255.255.255.255&"\
              "sport=0&"\
              "sport_mask=0&"\
              "dport=0&"\
              "dport_mask=0&"\
              "protocol=0&"\
              "protocol_mask=0&"\
              "action_type=3&"\
              "action_data=%d"\

std::vector<LinkInfo> links;

[[noreturn]] void taskSend() {
    while (true) {
        for (auto &link:links) {
            link.sendARPRequest();

            std::this_thread::sleep_for(std::chrono::microseconds(1000));  //1000 不要改
        }
        std::this_thread::sleep_for(std::chrono::microseconds(TASK_SEND_ARP_REQ_INTERVAL_MS * 1000));
    }
}

[[noreturn]] void taskReceive(LinkInfo &link) {
#define MAXBYTES2CAPTURE 2048
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter{};
    bpf_u_int32 netaddr = 0, mask = 0;
    auto descr = pcap_open_live(link.sourceIfaceName.c_str(), MAXBYTES2CAPTURE, 0, 512, errbuf);
    if (descr == nullptr) {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
    }
    if (pcap_lookupnet(link.sourceIfaceName.c_str(), &netaddr, &mask, errbuf) == -1) {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
    }
    if (pcap_compile(descr, &filter, "arp", 1, mask) == -1) {
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr));
        exit(1);
    }
    if (pcap_setfilter(descr, &filter) == -1) {
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr));
        exit(1);
    }
    while (true) {
        struct pcap_pkthdr pkthdr{};
        auto packet = pcap_next(descr, &pkthdr);
        if (packet == nullptr) {  /* Get one packet */

            continue;
        }

        auto arpheader = (struct arp_hdr *) (packet + 14); /* Point to the ARP header */

        debug("\n\nReceived Packet Size: %d bytes\n", pkthdr.len);
        debug("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
        debug("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
        debug("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");

        /* If is Ethernet and IPv4, print packet contents */

        if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800 &&
            arpheader->spa == inet_addr(link.targetIp.c_str())) {
            link.update();
        }

    }
}

void linkControl(LinkInfo &link, int mode) {
#ifdef FORWARD_FEATURE
#define FORWARD_DESTINATION_IP "193.168.1.2"
    if(mode==1){
        struct tcam_key key={0};
            struct tcam_mask mask={0};
            key.dip=inet_addr(FORWARD_DESTINATION_IP);
            mask.dip=0xffffffff;
            FpgaUtil::writeRawTCAM(link.tcamIndex,key,mask);
            FpgaUtil::writeRawAction(link.tcamIndex,FpgaUtil::ACTIONS::ACTION_TO_PORT,link.portIndex);
    }else{
        FpgaUtil::disableTCAM(link.tcamIndex);
    }
#endif
// TODO 添加上升沿触发，防止资源频繁使用
// 状态变化->触发，状态不变->保持
// 根据link.latestStatus判断
      std::cout << link.targetIp << " set to " << (mode == 0 ? "down" : "up") << std::endl;
      httplib::Client cli(ADDR,PORT);
      char buf[1000];
      sprintf(buf, DATA_TMPL, link.tcamIndex, mode, link.portIndex);
      cli.set_connection_timeout(0, 300); // 300 milliseconds -> 1 ms ->30 ms
      //cli.set_read_timeout(5, 0); // 5 seconds
      //cli.set_write_timeout(5, 0); // 5 seconds

      if(mode != link.latestStatus){
          link.latestStatus = mode;
          std::cout<<"mode: "<<link.latestStatus<<std::endl;
          auto&& res=cli.Post(PATH, buf, "application/x-www-form-urlencoded");
          std::cout << "sended!" << std::endl;
          std::cout<<res->body<<std::endl;
      }
}

[[noreturn]] void taskAging() {
    while (true) {
        for (auto &link:links) {
            if (link.checkTimeout() > TIMEOUT_MS) {
                linkControl(link, 0);
            } else {
                linkControl(link, 1);
            }
            std::this_thread::sleep_for(std::chrono::microseconds(1000)); //1000 不要改
        }
        std::this_thread::sleep_for(std::chrono::microseconds(TASK_AGING_CHECK_INTERVAL_MS * 1000));
    }
}

volatile int running = 1;

void SIGINTHandler(int sig) {
    switch (sig) {
        case SIGINT:
            running = 0;
            break;
    }
};

int main() {
    ini::IniFile linkConf;
#ifdef FORWARD_FEATURE
    FpgaUtil::init();
#endif
    linkConf.load("linkmon.ini");
    try {
        for (auto &section:linkConf) {
            links.push_back(std::move(LinkInfo(section.second["targetIp"].as<std::string>(),
                                               section.second["portIndex"].as<int>(),
                                               section.second["tcamIndex"].as<int>(),
                                               static_cast<std::string>(section.first))));
        }
        if (links.empty()) {
            raise(SIGABRT);
        }
    } catch (std::exception e) {
        std::cout << "Invalid linkmon.ini" << std::endl;
        std::cout << e.what() << std::endl;
    }

    /*
    for (auto &link:links) {
        new std::thread(taskReceive, std::ref(link));
    }
    */
    std::thread sendThread(taskSend);
    sendThread.detach();
    std::thread agingThread(taskAging);
    agingThread.detach();

    signal(SIGINT, SIGINTHandler);  //handle "ctrl+c"
    while (running) {
        std::this_thread::sleep_for(std::chrono::microseconds(100000));
    }
    return 0;
}
