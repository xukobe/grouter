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
int linkstate[MAX_ROUTER_NUMBER][MAX_ROUTER_NUMBER];

uint32_t seq = 0; //Sequence number for LSA

int OSPFInit() {
    int i = 0;
    //Xuepeng: set number counter to 0
    neigharray.count = 0;
    seq = 0;
    for (i = 0; i < MAX_INTERFACES; i++) {
        neigharray.neighbors[i].isalive = FALSE;
    }

    routerarray.count = 0;

    for (i = 0; i < MAX_ROUTER_NUMBER; i++) {
        routerarray.routers[i].isempty = TRUE;
    }
    
    

    //    neigharray.count = 1;
    //    neigharray.neighbors[1].isalive = TRUE;
    //    neigharray.neighbors[1].ip[0] = 0xff;
    //    neigharray.neighbors[1].ip[1] = 0xff;
    //    neigharray.neighbors[1].ip[2] = 0xff;
    //    neigharray.neighbors[1].ip[3] = 0xff;
    //    neigharray.neighbors[1].interface_id = 1;
    //    neigharray.neighbors[1].netmask[0] = 0xff;
    //    neigharray.neighbors[1].netmask[1] = 0xff;
    //    neigharray.neighbors[1].netmask[2] = 0xff;
    //    neigharray.neighbors[1].netmask[3] = 0x00;
    //    neigharray.neighbors[1].isStub = FALSE;
    //    time(&neigharray.neighbors[1].timestamp);
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
                encapsulationForOSPF(pkt, netarray.elem[i]);

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

void *OSPFCheckDead(void* ptr) {
    int i;
    while (1) {
        pthread_testcancel();
        for (i = 0; i < MAX_INTERFACES; i++) {
            if (neigharray.neighbors[i].isalive) {
                time_t time_current = time(0);
                time_t time_neighbour = neigharray.neighbors[i].timestamp;
                int v = time_current - time_neighbour;
                if (v > DEFAULT_DEAD_INTERVAL) {
                    neigharray.neighbors[i].isalive = FALSE;
                }
            }
        }
        sleep(10);
    }
}

int OSPFInitCheckDeadThread() {
    int threadstat, threadid;
    threadstat = pthread_create((pthread_t *) & threadid, NULL, (void *) OSPFCheckDead, NULL);
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
        if (neigharray.neighbors[i].isalive) {
            gpacket_t* pkt = (gpacket_t*) malloc(sizeof (gpacket_t));
            ip_packet_t *ip_pkt = (ip_packet_t*) (pkt->data.data);
            ospf_header_t* ospf_pkt = (ospf_header_t*) (ip_pkt + 1);
            ospf_lsa_header_t* lsa_header = (ospf_lsa_header_t*) (ospf_pkt + 1);
            lsa_data_t* lsa_data = (lsa_data_t*) (lsa_header + 1);
            uchar network[4];
            int neighCounter = 0;
            //Fill in the lsa data
            printf("OSPFSendLSA: 1\n");
            lsa_data->allZeors = 0;
            lsa_data->numberOfLinks = neigharray.count;
            for (j = 0; j < MAX_INTERFACES; j++) {
                printf("OSPFSendLSA: 2\n");
                if (neigharray.neighbors[j].isalive) {
                    printf("OSPFSendLSA: 3\n");
                    for (k = 0; k < 4; k++)
                        network[k] = neigharray.neighbors[j].netmask[k] & neigharray.neighbors[j].ip[k];
                    printf("OSPFSendLSA: 4\n");
                    COPY_IP(lsa_data->elem[neighCounter].linkID, gHtonl(tmpbuf, network));
                    for (k = 0; k < 5; k++)
                        lsa_data->elem[neighCounter].allZeros[k] = 0;
                    printf("OSPFSendLSA: 5\n");
                    lsa_data->elem[neighCounter].metrics = 1;
                    printf("neighbors netmask %s\n", IP2Dot(tmpbuf, neigharray.neighbors[j].netmask));
                    printf("neighbors routeraddress %s\n", IP2Dot(tmpbuf, netarray.elem[neigharray.neighbors[j].interface_id]->ip_addr));
                    if (neigharray.neighbors[j].isStub) {
                        COPY_IP(lsa_data->elem[neighCounter].linkData, gHtonl(tmpbuf, neigharray.neighbors[j].netmask));
                        lsa_data->elem[neighCounter].linkType = STUB;
                    } else {
                        COPY_IP(lsa_data->elem[neighCounter].linkData, gHtonl(tmpbuf, netarray.elem[neigharray.neighbors[j].interface_id]->ip_addr));
                        lsa_data->elem[neighCounter].linkType = ANY_TO_ANY;
                    }
                    printf("OSPFSendLSA: 6\n");
                    neighCounter++;
                }
            }
            printf("OSPFSendLSA: 7\n");
            //Fill in the lsa_header
            lsa_header->age = 0;
            lsa_header->type = 1;
            COPY_IP(lsa_header->linkstateid, gHtonl(tmpbuf, netarray.elem[neigharray.neighbors[i].interface_id]->ip_addr));
            COPY_IP(lsa_header->adrouter, gHtonl(tmpbuf, netarray.elem[neigharray.neighbors[i].interface_id]->ip_addr));
            lsa_header->seq = seq;
            lsa_header->checksum = 0;
            lsa_header->len = sizeof (ospf_lsa_header_t) + sizeof (lsa_data_t)-(MAX_INTERFACES - neighCounter) * sizeof (lsa_elem_t);
            
            printf("OSPFSendLSA: 8\n");
            //Fill in the ospf header;
            ospf_pkt->version = 2;
            ospf_pkt->type = 4;
            ospf_pkt->msglen = sizeof (ospf_header_t) + lsa_header->len;
            COPY_IP(ospf_pkt->ip_src, gHtonl(tmpbuf, netarray.elem[neigharray.neighbors[i].interface_id]->ip_addr));
            ospf_pkt->areaID = 0;
            ospf_pkt->authtype = 0;
            ospf_pkt->checksum = checksum((uchar *) ospf_pkt, ospf_pkt->msglen / 2);

            //Fill in the IP header
            encapsulationForOSPF(pkt, netarray.elem[neigharray.neighbors[i].interface_id]);

            printf("Sending %d\n", i);

            printf("IP packet: version %d\n", ip_pkt->ip_version);
            printf("OSPF packet: version %d Source IP %u.%u.%u.%u\n", ospf_pkt->version, ospf_pkt->ip_src[0], ospf_pkt->ip_src[1], ospf_pkt->ip_src[2], ospf_pkt->ip_src[3]);
            printf("LSA data: Number of Links %d \n", lsa_data->numberOfLinks);

            IPSend2Output(pkt);
        }
    }
    seq++;

}

void *OSPFRunLSA(void* ptr){
    while(1){
        OSPFSendLSAMessage();
        sleep(15);
    }
}

int OSPFInitLSAThread(){
    int threadstat, threadid;

    threadstat = pthread_create((pthread_t *) & threadid, NULL, (void *) OSPFRunLSA, NULL);
    printf("[OSPF] Thread creating!\n");
    if (threadstat != 0) {
        printf("[OSPF] Thread creation failed!\n");
        verbose(1, "[OSPFInitLSAThread]:: unable to create thread.. ");
        return -1;
    }
    printf("[OSPF] Thread created!\n");
    return threadid;
}

void OSPFPacketProcess(gpacket_t* in_packet) {
    int hello_neighbors_size = 0;
    int i = 0;
    int j = 0;
    char tmpbuf[MAX_TMPBUF_LEN];
    ip_packet_t *ip_pkt = (ip_packet_t*) (in_packet->data.data);
    ospf_header_t* ospf_pkt = (ospf_header_t*) (ip_pkt + 1);

    printf("IP packet: version %d\n", ip_pkt->ip_version);
    printf("OSPF packet: version %d Source IP %u.%u.%u.%u\n", ospf_pkt->version, ospf_pkt->ip_src[0], ospf_pkt->ip_src[1], ospf_pkt->ip_src[2], ospf_pkt->ip_src[3]);

    if (ospf_pkt->type == 1) {

        ospf_hello_data_t* hello_data = (ospf_hello_data_t*) (ospf_pkt + 1);
        printf("Hello data: Hello Interval %d \n", hello_data->helloInterval);
        hello_neighbors_size = MAX_INTERFACES - (sizeof (ospf_header_t) + sizeof (ospf_hello_data_t) - ospf_pkt->msglen) / sizeof (neigh_ip_t);

        for (i = 0; i < hello_neighbors_size; i++) {
            printf("Hello data neighbors %d: %u.%u.%u.%u\n", i + 1, hello_data->neighbors[i].ip[0], hello_data->neighbors[i].ip[1], hello_data->neighbors[i].ip[2], hello_data->neighbors[i].ip[3]);
        }

        if (hello_updateTheNeighbors(in_packet)) {
            //do something
            //recalculate the algorithm
            //initiate LSA message to neighbor.
            OSPFSendLSAMessage();
            printf("Need update!");
        }

    } else if (ospf_pkt->type == 4) {
        ospf_lsa_header_t* lsa_header = (ospf_lsa_header_t*) (ospf_pkt + 1);
        lsa_data_t* lsa_data = (lsa_data_t*) (lsa_header + 1);

        //forward or not
        if (updateRouterArray(lsa_header)) {
            //forward
            for (i = 0; i < MAX_INTERFACES; i++) {
                if (neigharray.neighbors[i].isalive && neigharray.neighbors[i].interface_id!=in_packet->frame.src_interface) {
                    gpacket_t* gpkt = malloc(sizeof (gpacket_t));
                    memcpy(gpkt, in_packet, sizeof (gpacket_t));
                    printf("Interface %d:%d\n", i, netarray.elem[i]->interface_id);
                    encapsulationForOSPF(gpkt, netarray.elem[i]);
                    IPSend2Output(gpkt);
                }
            }
        }

        printf("LSA header link state id %s\n", IP2Dot(tmpbuf, lsa_header->linkstateid));
        printf("LSA data number of links: %d\n", lsa_data->numberOfLinks);
        printf("LSA data first element ip:%s\n", IP2Dot(tmpbuf + 20, lsa_data->elem[0].linkID));
    }

}

//try to update Router information, if the packet is duplicated return false

bool updateRouterArray(ospf_lsa_header_t* lsa_header) {
    int i, j, k;
    lsa_data_t* lsa_data = (lsa_data_t*) (lsa_header + 1);
    uchar adRouterIP[4];
    char tmpbuf[MAX_TMPBUF_LEN];
    bool isFound = FALSE;
    bool duplicated = FALSE;
    router_t *router;
    COPY_IP(adRouterIP, gNtohl(tmpbuf, lsa_header->adrouter));
    printf("updateRouterArray 1\n");
    for (i = 0; i < MAX_ROUTER_NUMBER; i++) {
        if (!routerarray.routers[i].isempty) {
            printf("updateRouterArray 2\n");
            router = &(routerarray.routers[i]);
            for (j = 0; j < router->entryCount; j++) {
                printf("Router->entries[j] %s\n", IP2Dot(tmpbuf, router->entries[j].linkdata.routerAddress));
                printf("lsa_header->adrouter %s\n", IP2Dot(tmpbuf, adRouterIP));
                if (COMPARE_IP(router->entries[j].linkdata.routerAddress, adRouterIP) == 0) {
                    printf("updateRouterArray 3\n");
                    isFound = TRUE;
                    if (router->seq < lsa_header->seq) {
                        printf("updateRouterArray 4\n");
                        duplicated = FALSE;
                        router->seq = lsa_header->seq;
                        router->entryCount = lsa_data->numberOfLinks;
                        for (k = 0; k < router->entryCount; k++) {
                            if (lsa_data->elem[k].linkType == 2) {
                                router->entries[k].isStub = FALSE;
                                COPY_IP(router->entries[k].network, gNtohl(tmpbuf, lsa_data->elem[k].linkID));
                                COPY_IP(router->entries[k].linkdata.routerAddress, gNtohl(tmpbuf, lsa_data->elem[k].linkData));
                            } else if (lsa_data->elem[k].linkType == 3) {
                                router->entries[k].isStub = TRUE;
                                COPY_IP(router->entries[k].network, gNtohl(tmpbuf, lsa_data->elem[k].linkID));
                                COPY_IP(router->entries[k].linkdata.netmask, gNtohl(tmpbuf, lsa_data->elem[k].linkData));
                            }
                        }

                    } else {
                        duplicated = TRUE;
                    }
                    break;
                }
            }
            printf("updateRouterArray 5\n");
            if (isFound == TRUE) {
                return !duplicated;
            }
        }
    }
    printf("updateRouterArray 6\n");
    if (isFound == FALSE) {
        printf("updateRouterArray 7\n");
        for (i = 0; i < MAX_ROUTER_NUMBER; i++) {
            if (routerarray.routers[i].isempty) {
                printf("updateRouterArray 8\n");
                router = &(routerarray.routers[i]);
                duplicated = FALSE;
                router->seq = lsa_header->seq;
                printf("seq:%d\n",lsa_header->seq);
                router->entryCount = lsa_data->numberOfLinks;
                printf("Number of Links:%d\n",lsa_data->numberOfLinks);
                for (k = 0; k < router->entryCount; k++) {
                    if (lsa_data->elem[k].linkType == 2) {
                        router->entries[k].isStub = FALSE;
                        COPY_IP(router->entries[k].network, gNtohl(tmpbuf, lsa_data->elem[k].linkID));
                        COPY_IP(router->entries[k].linkdata.routerAddress, gNtohl(tmpbuf, lsa_data->elem[k].linkData));
                    } else if (lsa_data->elem[k].linkType == 3) {
                        router->entries[k].isStub = TRUE;
                        COPY_IP(router->entries[k].network, gNtohl(tmpbuf, lsa_data->elem[k].linkID));
                        COPY_IP(router->entries[k].linkdata.netmask, gNtohl(tmpbuf, lsa_data->elem[k].linkData));
                    }
                }
                router->isempty = FALSE;
                break;
            }
        }
    }
    printf("updateRouterArray 9\n");
    return TRUE;
}

//update the neighbors information and return true if any value (except timestamp) changed

bool hello_updateTheNeighbors(gpacket_t* in_pkt) {
    bool update = FALSE;
    ip_packet_t* ip_pkt = (ip_packet_t*) (in_pkt->data.data);
    ospf_header_t* ospf_pkt = (ospf_header_t*) (ip_pkt + 1);
    ospf_hello_data_t* hello_data = (ospf_hello_data_t*) (ospf_pkt + 1);
    char tmpbuf[MAX_TMPBUF_LEN];
    int interface_id = in_pkt->frame.src_interface;

    uchar pkt_ip[4];

    uchar netmask[4];
    uint16_t helloInterval;
    uint32_t deadInterval;
    uchar designatedIP[4];
    uchar backupdesignatedIP[4];
    helloInterval = hello_data->helloInterval;
    deadInterval = hello_data->deadInterval;
    COPY_IP(designatedIP, hello_data->designatedIP);
    COPY_IP(backupdesignatedIP, hello_data->backupdesignatedIP);
    COPY_IP(pkt_ip, gNtohl(tmpbuf, ip_pkt->ip_src));
    COPY_IP(netmask, hello_data->netmask);
    printf("Hello:original %s\n", IP2Dot(tmpbuf, neigharray.neighbors[interface_id].ip));
    printf("Hello:pkt_ip %s\n", IP2Dot(tmpbuf, pkt_ip));
    //printf("Hello:IP changed %s->%s\n",IP2Dot(tmpbuf,neigharray.neighbors[interface_id].ip),IP2Dot(tmpbuf,pkt_ip));
    printf("Hello:Compare:%d\n", COMPARE_IP(neigharray.neighbors[interface_id].ip, pkt_ip));
    if (COMPARE_IP(neigharray.neighbors[interface_id].ip, pkt_ip) != 0) {
        printf("Hello:IP changed %s->%s\n", IP2Dot(tmpbuf, neigharray.neighbors[interface_id].ip), IP2Dot(tmpbuf + 20, pkt_ip));
        COPY_IP(neigharray.neighbors[interface_id].ip, pkt_ip);
        update = TRUE;
    }

    if (COMPARE_IP(neigharray.neighbors[interface_id].netmask, netmask) != 0) {
        printf("Hello:Netmask changed %s->%s\n", IP2Dot(tmpbuf, neigharray.neighbors[interface_id].netmask), IP2Dot(tmpbuf + 20, netmask));
        COPY_IP(neigharray.neighbors[interface_id].netmask, netmask);
        update = TRUE;
    }

    if (COMPARE_IP(neigharray.neighbors[interface_id].designatedIP, designatedIP) != 0) {
        printf("Hello:DesignatedIP changed %s->%s\n", IP2Dot(tmpbuf, neigharray.neighbors[interface_id].designatedIP), IP2Dot(tmpbuf + 20, designatedIP));
        COPY_IP(neigharray.neighbors[interface_id].designatedIP, designatedIP);
        update = TRUE;
    }

    if (COMPARE_IP(neigharray.neighbors[interface_id].backupdesignatedIP, backupdesignatedIP) != 0) {
        printf("Hello:BackupDesignatedIP changed %s->%s\n", IP2Dot(tmpbuf, neigharray.neighbors[interface_id].backupdesignatedIP), IP2Dot(tmpbuf + 20, backupdesignatedIP));
        COPY_IP(neigharray.neighbors[interface_id].backupdesignatedIP, backupdesignatedIP);
        update = TRUE;
    }

    if (helloInterval != neigharray.neighbors[interface_id].helloInterval) {
        printf("Hello:HelloInterval changed %d->%d\n", neigharray.neighbors[interface_id].helloInterval, helloInterval);
        neigharray.neighbors[interface_id].helloInterval = helloInterval;
        update = TRUE;
    }

    if (deadInterval != neigharray.neighbors[interface_id].deadInterval) {
        printf("Hello:DeadInterval changed %d->%d\n", neigharray.neighbors[interface_id].deadInterval, deadInterval);
        neigharray.neighbors[interface_id].deadInterval = deadInterval;
        update = TRUE;
    }
    
    if (interface_id!=neigharray.neighbors[interface_id].interface_id){
        neigharray.neighbors[interface_id].interface_id=interface_id;
        update=TRUE;
    }

    if(neigharray.neighbors[interface_id].isalive == FALSE)
    {
        neigharray.count++;
        neigharray.neighbors[interface_id].isalive=TRUE;
        update=TRUE;
    }
    time(&(neigharray.neighbors[interface_id].timestamp));
    //the rest of the properties are not very important, we ignored here.
    return update;
}

bool checkInterfaceIsAlive(int interface_id) {
    if (!neigharray.neighbors[interface_id].isalive) {
        return FALSE;
    } else {
        return TRUE;
    }
}

void encapsulationForOSPF(gpacket_t* pkt, interface_t* interf) {
    char tmpbuf[MAX_TMPBUF_LEN];
    ushort cksum = 0;
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
    printf("encapsulation: dst_interface: %d\n", pkt->frame.dst_interface);
    //jingsi: set ip_src to the IP address of current interface IP.
    printf("encapsulation: %s\n", IP2Dot(tmpbuf, interf->ip_addr));
    COPY_IP(ip_pkt->ip_src, gHtonl(tmpbuf, interf->ip_addr));
    printf("encapsulation: %s\n", IP2Dot(tmpbuf, ip_pkt->ip_src));
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
////
// TEST SAMPLE
//#include <stdio.h>
//#include <stdlib.h>
//
//#define false 0
//#define true 1
//#define MAX_ROUTER_NUMBER 5
//int main() {
//    int dist[MAX_ROUTER_NUMBER];
//    int size = 5;
//    int cost[MAX_ROUTER_NUMBER][MAX_ROUTER_NUMBER] = {
//        {0, 1, 999, 1, 999},
//        {1, 0, 1, 999, 1},
//        {999, 1, 0, 1, 1},
//        {1, 999, 1, 0, 1},
//        {999, 1, 1, 1, 0}
//    };
//    int next[MAX_ROUTER_NUMBER][MAX_ROUTER_NUMBER];
//    djAlg(&cost[0][0], &next[0][0], size);
//    int i,j ;
//    printf("shortest path:\n");
//    for(i = 0; i< size; i++){
//        for(j = 0; j< size; j++){
//        printf("%d->%d:cost%d next hop is:%d\t",i,j,cost[i][j],next[i][j]);
//        }
//        printf("\n");
//    }
//
//    return (EXIT_SUCCESS);
//}

void OSPFViewRouters() {
    int i, j;
    char tmpbuf[MAX_TMPBUF_LEN];
    for (i = 0; i < MAX_ROUTER_NUMBER; i++) {
        if (!routerarray.routers[i].isempty) {
            printf("Router %d information: entryCount: %d, seq %d\n", i, routerarray.routers[i].entryCount, routerarray.routers[i].seq);
            for (j = 0; j < routerarray.routers[i].entryCount; j++)
                printf("\t\tnetwork %s, linkdata %s\n", IP2Dot(tmpbuf, routerarray.routers[i].entries[j].network), IP2Dot(tmpbuf + 20, routerarray.routers[i].entries[j].linkdata.routerAddress));
        }
    }
}

void handleUML(gpacket_t* pkt){
    char tmpbuf[MAX_TMPBUF_LEN];
    uchar netmask[4] = DEFAULT_NETMASK;
    int interface_id = pkt->frame.src_interface;
    ip_packet_t* ip_pkt = (ip_packet_t*)pkt->data.data;
    COPY_IP(neigharray.neighbors[interface_id].ip, gNtohl(tmpbuf, ip_pkt->ip_src));
    COPY_IP(neigharray.neighbors[interface_id].netmask, netmask);
    printf("HandleUML,%d\n",IP2Dot(tmpbuf,netmask));
    neigharray.neighbors[interface_id].interface_id=interface_id;
    neigharray.neighbors[interface_id].isStub=TRUE;
    if(neigharray.neighbors[interface_id].isalive==FALSE){
        neigharray.neighbors[interface_id].isalive=TRUE;
        neigharray.count++;
    }
    OSPFSendLSAMessage();
}

/*
 * FUNNAME:ajAlg
 * @input :
 *      cost[][MAX_ROUTER_NUMBER] : path cost
 *      next[][] : next hop router
 *      size : number of considered routers
 * call : ajAlg(&cost[0][0]，&next[0][0], size)
 */
void djAlg(int cost[][MAX_ROUTER_NUMBER], int next[][MAX_ROUTER_NUMBER], int size) {
    int isFinal[MAX_ROUTER_NUMBER], isFirstHop[MAX_ROUTER_NUMBER];
    int k, i, v, w, min;
    printf("\nshortest path:\n");
    for (k = 0; k < size; k++) {
        // initial shortest path(not the result)          
        for (v = 0; v < size; v++) {
            isFinal[v] = 0;
            isFirstHop[v] = 1;
            next[k][v] = v;
        }
        // dis(k-k)=0   is the final distance         
        isFinal[k] = 1;
        // vo - the other points:
        for (i = 0; i < size - 1; i++) {
            //initial shortest path = inf
            min = 999;
            // looking for shortest path         
            for (w = 0; w < size; w++) {
                if (!isFinal[w] && cost[k][w] < min) {
                    min = cost[k][w];
                    //v: current considered destination
                    v = w;
                }
            }
            isFinal[v] = 1;
            // add new path  
            for (w = 0; w < size; w++) {
                // update distance matrix           
                if (!isFinal[w] && cost[k][v] + cost[v][w] < cost[k][w]) {
                    if (isFirstHop[w] == 1) {
                        if (isFirstHop[v] == 0)
                            next[k][w] = next[k][v];
                        else
                            next[k][w] = v;
                        isFirstHop[w] = 0;
                    }
                    cost[k][w] = cost[k][v] + cost[v][w];
                }
            }
        }
    }
}

