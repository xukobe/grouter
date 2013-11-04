/*
 * ospf.c (collection of functions that implement the Open  (OSPF).
 * AUTHOR: Original version by Xuepeng
 *         Revised by Haowei
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
neigh_array_t neigharray;
router_array routerarray;
int linkstate[][];
uint32_t seq = 0; //Sequence number for LSA

int OSPFInit() {
    int i = 0;
    //Xuepeng: set number counter to 0
    neigharray.count = 0;
    seq = 0;
    for (i = 0; i < MAX_INTERFACES; i++) {
        neigharray.neighbors[i].isalive = FALSE;
    }
    neigharray.count = 1;
    neigharray.neighbors[1].isalive = TRUE;
    neigharray.neighbors[1].ip[0] = 0xff;
    neigharray.neighbors[1].ip[1] = 0xff;
    neigharray.neighbors[1].ip[2] = 0xff;
    neigharray.neighbors[1].ip[3] = 0xff;
    neigharray.neighbors[1].interface_id = 1;
    neigharray.neighbors[1].netmask[0] = 0xff;
    neigharray.neighbors[1].netmask[1] = 0xff;
    neigharray.neighbors[1].netmask[2] = 0xff;
    neigharray.neighbors[1].netmask[3] = 0x00;
    neigharray.neighbors[1].isStub = FALSE;
    time(&neigharray.neighbors[1].timestamp);
    return EXIT_SUCCESS;
}

void *OSPFSendHelloMessage(void* ptr) {
    int i = 0;
    int j = 0;
    char tmpbuf[MAX_TMPBUF_LEN];
    uchar netmask[4] = DEFAULT_NETMASK;
    uchar designated[4] = DEFAULT_DESIGNATED_ROUTER_IP;
    uchar backupdesignated[4] = DEFAULT_BACKUP_DESIGNATED_ROUTER_IP;

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    printf("%d\n", netarray.count);
    while (1) {
        pthread_testcancel();
        for (i = 0; i < MAX_INTERFACES; i++) {
            if (netarray.elem[i] != NULL) {
                gpacket_t* pkt = (gpacket_t*) malloc(sizeof (gpacket_t));
                ip_packet_t *ip_pkt = (ip_packet_t*) (pkt->data.data);
                ospf_header_t* ospf_pkt = (ospf_header_t*) (ip_pkt + 1);
                ospf_hello_data_t* hello_data = (ospf_hello_data_t*) (ospf_pkt + 1);
                int neighCounter = 0;
                //Fill in the hello data;
                COPY_IP(hello_data->netmask, gHtonl(tmpbuf, netmask));
                hello_data->helloInterval = DEFAULT_HELLO_INTERVAL;
                hello_data->options = 0;
                hello_data->priority = DEFAULT_PRIORITY;
                hello_data->deadInterval = DEFAULT_DEAD_INTERVAL;
                COPY_IP(hello_data->backupdesignatedIP, gHtonl(tmpbuf, backupdesignated));
                COPY_IP(hello_data->designatedIP, gHtonl(tmpbuf, designated));
                for (j = 0; j < MAX_INTERFACES; j++) {
                    if (neigharray.neighbors[j].isalive) {
                        COPY_IP(hello_data->neighbors[neighCounter++].ip, gHtonl(tmpbuf, neigharray.neighbors[j].ip));
                    }
                }
                //                if(neighCounter)
                //                for(j=neighCounter;j<MAX_INTERFACES;j++){
                //                    COPY_IP(hello_data->neighbors[j].ip,gHtonl(tmpbuf,end_sign));
                //                }

                //Fill in the ospf header;
                ospf_pkt->version = 2;
                ospf_pkt->type = 1;
                ospf_pkt->msglen = sizeof (ospf_header_t) + sizeof (ospf_hello_data_t)-(MAX_INTERFACES - neighCounter) * sizeof (neigh_ip_t);
                COPY_IP(ospf_pkt->ip_src, gHtonl(tmpbuf, netarray.elem[i]->ip_addr));
                ospf_pkt->areaID = 0;
                ospf_pkt->authtype = 0;
                ospf_pkt->checksum = checksum((uchar *) ospf_pkt, ospf_pkt->msglen / 2);

                //Fill in the ip header
                encapsulationForOSPF(pkt,netarray.elem[i]);
                
                printf("Sending %d\n", i);

                printf("IP packet: version %d\n", ip_pkt->ip_version);
                printf("OSPF packet: version %d Source IP %u.%u.%u.%u\n", ospf_pkt->version, ospf_pkt->ip_src[0], ospf_pkt->ip_src[1], ospf_pkt->ip_src[2], ospf_pkt->ip_src[3]);
                printf("Hello data: Hello Interval %d \n", hello_data->helloInterval);

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

void OSPFSendLSAMessage() {
    int i = 0, j = 0, k = 0;
    char tmpbuf[MAX_TMPBUF_LEN];
//    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
//
//    pthread_testcancel();
    for (i = 0; i < MAX_INTERFACES; i++) {
        if (netarray.elem[i] != NULL) {
            gpacket_t* pkt = (gpacket_t*) malloc(sizeof (gpacket_t));
            ip_packet_t *ip_pkt = (ip_packet_t*) (pkt->data.data);
            ospf_header_t* ospf_pkt = (ospf_header_t*) (ip_pkt + 1);
            ospf_lsa_header_t* lsa_header = (ospf_lsa_header_t*) (ospf_pkt + 1);
            lsa_data_t* lsa_data = (lsa_data_t*) (lsa_header + 1);
            uchar network[4];
            int neighCounter = 0;
            //Fill in the lsa data
            lsa_data->allZeors = 0;
            lsa_data->numberOfLinks = neigharray.count;
            for (j = 0; j < MAX_INTERFACES; j++) {
                if (neigharray.neighbors[j].isalive) {
                    for (k = 0; k < 4; k++)
                        network[k] = neigharray.neighbors[j].netmask[k] & neigharray.neighbors[j].ip[k];
                    COPY_IP(lsa_data->elem[neighCounter].linkID, gHtonl(tmpbuf, network));
                    for (k = 0; k < 5; k++)
                        lsa_data->elem[neighCounter].allZeros[k] = 0;
                    lsa_data->elem[neighCounter].metrics = 1;
                    if (neigharray.neighbors[j].isStub) {
                        COPY_IP(lsa_data->elem[neighCounter].linkData, gHtonl(tmpbuf, neigharray.neighbors[j].netmask));
                        lsa_data->elem[neighCounter].linkType = STUB;
                    } else {
                        COPY_IP(lsa_data->elem[neighCounter].linkData, gHtonl(tmpbuf, neigharray.neighbors[j].ip));
                        lsa_data->elem[neighCounter].linkType = ANY_TO_ANY;
                    }
                    neighCounter++;
                }
            }

            //Fill in the lsa_header
            lsa_header->age = 0;
            lsa_header->type = 1;
            COPY_IP(lsa_header->linkstateid, gHtonl(tmpbuf, netarray.elem[i]->ip_addr));
            COPY_IP(lsa_header->adrouter, gHtonl(tmpbuf, netarray.elem[i]->ip_addr));
            lsa_header->seq = seq;
            lsa_header->checksum = 0;
            lsa_header->len = sizeof (ospf_lsa_header_t) + sizeof (lsa_data_t)-(MAX_INTERFACES - neighCounter) * sizeof (lsa_elem_t);

            //Fill in the ospf header;
            ospf_pkt->version = 2;
            ospf_pkt->type = 4;
            ospf_pkt->msglen = sizeof (ospf_header_t) + lsa_header->len;
            COPY_IP(ospf_pkt->ip_src, gHtonl(tmpbuf, netarray.elem[i]->ip_addr));
            ospf_pkt->areaID = 0;
            ospf_pkt->authtype = 0;
            ospf_pkt->checksum = checksum((uchar *) ospf_pkt, ospf_pkt->msglen / 2);

            //Fill in the IP header
            encapsulationForOSPF(pkt,netarray.elem[i]);

            printf("Sending %d\n", i);

            printf("IP packet: version %d\n", ip_pkt->ip_version);
            printf("OSPF packet: version %d Source IP %u.%u.%u.%u\n", ospf_pkt->version, ospf_pkt->ip_src[0], ospf_pkt->ip_src[1], ospf_pkt->ip_src[2], ospf_pkt->ip_src[3]);
            printf("LSA data: Number of Links %d \n", lsa_data->numberOfLinks);

            IPSend2Output(pkt);
        }
    }
    seq++;

}

//int OSPFInitLSAThread(){
//    int threadstat, threadid;
//
//    threadstat = pthread_create((pthread_t *) & threadid, NULL, (void *) OSPFSendLSAMessage, NULL);
//    printf("[OSPF] Thread creating!\n");
//    if (threadstat != 0) {
//        printf("[OSPF] Thread creation failed!\n");
//        verbose(1, "[OSPFInitHelloThread]:: unable to create thread.. ");
//        return -1;
//    }
//    printf("[OSPF] Thread created!\n");
//    return threadid;
//}

void OSPFPacketProcess(gpacket_t* in_packet) {
    int hello_neighbors_size = 0;
    int i = 0;
    char tmpbuf[MAX_TMPBUF_LEN];
    ip_packet_t *ip_pkt = (ip_packet_t*) (in_packet->data.data);
    ospf_header_t* ospf_pkt = (ospf_header_t*) (ip_pkt + 1);
    
    printf("IP packet: version %d\n", ip_pkt->ip_version);
    printf("OSPF packet: version %d Source IP %u.%u.%u.%u\n", ospf_pkt->version, ospf_pkt->ip_src[0], ospf_pkt->ip_src[1], ospf_pkt->ip_src[2], ospf_pkt->ip_src[3]);
    
    if(ospf_pkt->type==1){

        ospf_hello_data_t* hello_data = (ospf_hello_data_t*) (ospf_pkt + 1);
        printf("Hello data: Hello Interval %d \n", hello_data->helloInterval);
        hello_neighbors_size = MAX_INTERFACES - (sizeof (ospf_header_t) + sizeof (ospf_hello_data_t) - ospf_pkt->msglen) / sizeof (neigh_ip_t);

        for (i = 0; i < hello_neighbors_size; i++) {
            printf("Hello data neighbors %d: %u.%u.%u.%u\n", i + 1, hello_data->neighbors[i].ip[0], hello_data->neighbors[i].ip[1], hello_data->neighbors[i].ip[2], hello_data->neighbors[i].ip[3]);
        }
        
        if(hello_updateTheNeighbors(in_packet)){
            //do something
            //recalculate the algorithm
            //initiate LSA message to neighbor.
            OSPFSendLSAMessage();
            printf("Need update!");
        }
        
    }
    else if(ospf_pkt->type==4){
        ospf_lsa_header_t* lsa_header = (ospf_lsa_header_t*) (ospf_pkt + 1);
        lsa_data_t* lsa_data = (lsa_data_t*) (lsa_header + 1);
        
        //forward or not
        
        printf("LSA header link state id %s\n",IP2Dot(tmpbuf, lsa_header->linkstateid));
        printf("LSA data number of links: %d\n",lsa_data->numberOfLinks);
        printf("LSA data first element ip:%s\n",IP2Dot(tmpbuf+20,lsa_data->elem[0].linkID));
    }

}

//update the neighbors information and return true if any value (except timestamp) changed
bool hello_updateTheNeighbors(gpacket_t* in_pkt){
    bool update=FALSE;
    ip_packet_t* ip_pkt = (ip_packet_t*) (in_pkt->data.data);
    ospf_header_t* ospf_pkt = (ospf_header_t*) (ip_pkt + 1);
    ospf_hello_data_t* hello_data = (ospf_hello_data_t*) (ospf_pkt + 1);
    char tmpbuf[MAX_TMPBUF_LEN];
    int interface_id=in_pkt->frame.src_interface;
    
    uchar pkt_ip[4];
    
    uchar netmask[4];
    uint16_t helloInterval;
    uint32_t deadInterval;
    uchar designatedIP[4];
    uchar backupdesignatedIP[4];
    helloInterval=hello_data->helloInterval;
    deadInterval=hello_data->deadInterval;
    COPY_IP(designatedIP,hello_data->designatedIP);
    COPY_IP(backupdesignatedIP,hello_data->backupdesignatedIP);
    COPY_IP(pkt_ip, gNtohl(tmpbuf, ip_pkt->ip_src));
    COPY_IP(netmask,hello_data->netmask);
    printf("Hello:original %s\n",IP2Dot(tmpbuf,neigharray.neighbors[interface_id].ip));
    printf("Hello:pkt_ip %s\n",IP2Dot(tmpbuf,pkt_ip));
    //printf("Hello:IP changed %s->%s\n",IP2Dot(tmpbuf,neigharray.neighbors[interface_id].ip),IP2Dot(tmpbuf,pkt_ip));
    printf("Hello:Compare:%d\n",COMPARE_IP(neigharray.neighbors[interface_id].ip, pkt_ip));
    if(COMPARE_IP(neigharray.neighbors[interface_id].ip, pkt_ip)!=0){
        printf("Hello:IP changed %s->%s\n",IP2Dot(tmpbuf,neigharray.neighbors[interface_id].ip),IP2Dot(tmpbuf+20,pkt_ip));
        COPY_IP(neigharray.neighbors[interface_id].ip, pkt_ip);
        update=TRUE;
    }
    
    if(COMPARE_IP(neigharray.neighbors[interface_id].netmask, netmask)!=0){
        printf("Hello:Netmask changed %s->%s\n",IP2Dot(tmpbuf,neigharray.neighbors[interface_id].netmask),IP2Dot(tmpbuf+20,netmask));
        COPY_IP(neigharray.neighbors[interface_id].netmask, netmask);
        update=TRUE;
    }
    
    if(COMPARE_IP(neigharray.neighbors[interface_id].designatedIP, designatedIP)!=0){
        printf("Hello:DesignatedIP changed %s->%s\n",IP2Dot(tmpbuf,neigharray.neighbors[interface_id].designatedIP),IP2Dot(tmpbuf+20,designatedIP));
        COPY_IP(neigharray.neighbors[interface_id].designatedIP, designatedIP);
        update=TRUE;
    }
    
    if(COMPARE_IP(neigharray.neighbors[interface_id].backupdesignatedIP, backupdesignatedIP)!=0){
        printf("Hello:BackupDesignatedIP changed %s->%s\n",IP2Dot(tmpbuf,neigharray.neighbors[interface_id].backupdesignatedIP),IP2Dot(tmpbuf+20,backupdesignatedIP));
        COPY_IP(neigharray.neighbors[interface_id].backupdesignatedIP, backupdesignatedIP);
        update=TRUE;
    }
    
    if(helloInterval!=neigharray.neighbors[interface_id].helloInterval){
        printf("Hello:HelloInterval changed %d->%d\n",neigharray.neighbors[interface_id].helloInterval,helloInterval);
        neigharray.neighbors[interface_id].helloInterval=helloInterval;
        update=TRUE;
    }
    
    if(deadInterval!=neigharray.neighbors[interface_id].deadInterval){
        printf("Hello:DeadInterval changed %d->%d\n",neigharray.neighbors[interface_id].deadInterval,deadInterval);
        neigharray.neighbors[interface_id].deadInterval=deadInterval;
        update=TRUE;
    }
    
    neigharray.neighbors[interface_id].isalive=TRUE;
    time(&(neigharray.neighbors[interface_id].timestamp));
    //the rest of the properties are not very important, we ignored here.
    return update;
}

bool checkInterfaceIsAlive(int interface_id){
    if(!neigharray.neighbors[interface_id].isalive){
        return FALSE;
    }
    else{
        return TRUE;
    }
}

void *OSPFCheckDead(void* ptr){
    while(1){
        
        //dosomething
        sleep(10);
    }
}

int OSPFInitCheckDeadThread(){
    
}

void encapsulationForOSPF(gpacket_t* pkt, interface_t* interf) {
    char tmpbuf[MAX_TMPBUF_LEN];
    ushort cksum=0;
    uchar dst_ip[4] = IP_BCAST_ADDR;
    uchar mac_addr[6] = MAC_BCAST_ADDR;
    ip_packet_t *ip_pkt = (ip_packet_t*) (pkt->data.data);
    ospf_header_t* ospf_pkt = (ospf_header_t*) (ip_pkt + 1);
    //Fill in the ip header
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
    ip_pkt->ip_pkt_len = htons(ip_pkt->ip_hdr_len * 4 + ospf_pkt->msglen);

    ip_pkt->ip_ttl = 64; // set TTL to default value
    ip_pkt->ip_cksum = 0; // reset the checksum field

    //printf("%d",netarray.elem[i]->interface_id);
    //jingsi: frame.dst_interface is outgoing interface.
    //jingsi: netarray.elem[i]-> interface_id is interface identifier.
    pkt->frame.dst_interface = interf->interface_id;

    //jingsi: set ip_src to the IP address of current interface IP.
    printf("encapsulation: %s\n",IP2Dot(tmpbuf,interf->ip_addr));
    COPY_IP(ip_pkt->ip_src, gHtonl(tmpbuf, interf->ip_addr));
    printf("encapsulation: %s\n",IP2Dot(tmpbuf,ip_pkt->ip_src));
    //jingsi: dest_ip is the broadcast IP
    COPY_IP(ip_pkt->ip_dst, gHtonl(tmpbuf, dst_ip));

    //jingsi:  frame.nxth_ip_addr is destination interface IP address
    COPY_IP(pkt->frame.nxth_ip_addr, gHtonl(tmpbuf, dst_ip));
    //xuepeng: an alternative method to bypass the ARP resolution.            
    pkt->frame.arp_valid = FALSE;
    pkt->frame.arp_bcast = TRUE;
    COPY_MAC(pkt->data.header.dst, mac_addr);

    printf("%s\n", IP2Dot(tmpbuf, ip_pkt->ip_dst));
    ip_pkt->ip_prot = OSPF_PROTOCOL;

    //compute the new checksum
    cksum = checksum((uchar *) ip_pkt, ip_pkt->ip_hdr_len * 2);
    printf("Checksum %d\n", cksum);
    ip_pkt->ip_cksum = htons(cksum);
    pkt->data.header.prot = htons(IP_PROTOCOL);

}

void djAlg(int** c,int** v, int size){
    
}
