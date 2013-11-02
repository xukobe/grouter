/*
 * ospf.c (collection of functions that implement the Open  (OSPF).
 * AUTHOR: Original version by Xuepeng
 *         Revised by ....
 * DATE:   Nov.1st 2013
 */

#include "message.h"
#include "grouter.h"
#include "routetable.h"
#include "protocols.h"
#include "gnet.h"
#include "ospf.h"
#include <stdlib.h>
#include <slack/err.h>
#include <netinet/in.h>
#include <string.h>

//Xuepeng: Should use broadcast, here we use point to point communication

extern interface_array_t netarray;

void *OSPFSendHelloMessage(void* ptr) {
    int i = 0;
    char tmpbuf[MAX_TMPBUF_LEN];
    uchar dst_ip[4] = IP_BCAST_ADDR;
    uchar mac_addr[6]=MAC_BCAST_ADDR;
    ushort cksum;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    printf("%d\n",netarray.count);
    while(1){
        pthread_testcancel();
        for (i = 0; i < MAX_INTERFACES; i++) {
            if(netarray.elem[i]!=NULL){
                gpacket_t* pkt = (gpacket_t*) malloc(sizeof (gpacket_t));
                ip_packet_t *ip_pkt = (ip_packet_t*) (pkt->data.data);
                ip_pkt->ip_version = 4;
                ip_pkt->ip_hdr_len = 5;
                ip_pkt->ip_tos = 0;
                ip_pkt->ip_identifier = IP_OFFMASK & random();
                RESET_DF_BITS(ip_pkt->ip_frag_off);
                RESET_MF_BITS(ip_pkt->ip_frag_off);
                ip_pkt->ip_frag_off = 0;
                
                // jingsi's job: change packet length
                //change pointer to type char * + 20 instead of ip_pkt + 20, then change pointer to type ospf_header_t
                //alternatively: ip_pkt +1 
                ip_pkt->ip_pkt_len = htons(ip_pkt->ip_hdr_len * 4);
                
       
                //printf("%d",netarray.elem[i]->interface_id);
                 //jingsi: frame.dst_interface is outgoing interface.
                //jingsi: netarray.elem[i]-> interface_id is interface identifier.
                pkt->frame.dst_interface = netarray.elem[i]->interface_id;
                
                //jingsi: set ip_src to the IP address of current interface IP.       
                COPY_IP(ip_pkt->ip_src, gHtonl(tmpbuf, netarray.elem[i]->ip_addr));
                
                //jingsi: dest_ip is the broadcast IP
                COPY_IP(ip_pkt->ip_dst, gHtonl(tmpbuf, dst_ip));
                
                //jingsi:  frame.nxth_ip_addr is destination interface IP address
                COPY_IP(pkt->frame.nxth_ip_addr, gHtonl(tmpbuf, dst_ip));
               //xuepeng: an alternative method to bypass the ARP resolution.            
                pkt->frame.arp_valid=FALSE;
                pkt->frame.arp_bcast=TRUE;
                COPY_MAC(pkt->data.header.dst,mac_addr);

                printf("%s\n",IP2Dot(tmpbuf,ip_pkt->ip_dst));
                ip_pkt->ip_prot=OSPF_PROTOCOL;

                //compute the new checksum
                cksum = checksum((uchar *) ip_pkt, ip_pkt->ip_hdr_len * 2);
                ip_pkt->ip_cksum = htons(cksum);
                pkt->data.header.prot = htons(IP_PROTOCOL);
                printf("Sending %d\n",i);
                IPSend2Output(pkt);
            }
        }
        sleep(10);
    }
}

int OSPFInitHelloThread() {
    int threadstat, threadid;

    threadstat = pthread_create((pthread_t *) & threadid, NULL, (void *) OSPFSendHelloMessage, NULL);
    printf("[OSPF] Thread creating!\n");
    if (threadstat != 0) {
        printf("[OSPF] Thread creation failed!\n");
        verbose(1, "[OSPFInitHelloThread]:: unable to create thread.. ");
        return -1;
    }
    printf("[OSPF] Thread created!\n");
    return threadid;
}