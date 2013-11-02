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

                ip_pkt->ip_pkt_len = htons(ip_pkt->ip_hdr_len * 4);
        //
                //printf("%d",netarray.elem[i]->interface_id);
                pkt->frame.dst_interface = netarray.elem[i]->interface_id;

                COPY_IP(ip_pkt->ip_src, gHtonl(tmpbuf, netarray.elem[i]->ip_addr));
                COPY_IP(ip_pkt->ip_dst, gHtonl(tmpbuf, dst_ip));
                COPY_IP(pkt->frame.nxth_ip_addr, gHtonl(tmpbuf, dst_ip));
                pkt->frame.arp_valid=FALSE;
                //an alternative method to bypass the ARP resolution.
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