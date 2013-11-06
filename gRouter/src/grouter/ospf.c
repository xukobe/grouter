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
extern route_entry_t route_tbl[MAX_ROUTES];
neigh_array_t neigharray;
router_array routerarray;
route_table_cache_array_t* rtcarray;
int linkstate[MAX_ROUTER_NUMBER][MAX_ROUTER_NUMBER];

ospf_handler_t handlers;

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
    
    rtcarray=(route_table_cache_array_t*)malloc(sizeof(route_table_cache_array_t));


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
    //printf("%d\n", netarray.count);
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

                //printf("Sending %d\n", i);

                //printf("IP packet: version %d\n", ip_pkt->ip_version);
                //printf("OSPF packet: version %d Source IP %u.%u.%u.%u\n", ospf_pkt->version, ospf_pkt->ip_src[0], ospf_pkt->ip_src[1], ospf_pkt->ip_src[2], ospf_pkt->ip_src[3]);
                //printf("Hello data: Hello Interval %d \n", hello_data->helloInterval);

                IPSend2Output(pkt);
            }
        }
        sleep(10);
    }
}

int OSPFInitHelloThread() {
    int threadstat, threadid;

    threadstat = pthread_create((pthread_t *) & handlers.hello_thread, NULL, (void *) OSPFSendHelloMessage, NULL);
    //printf("[OSPF] Thread creating!\n");
    if (threadstat != 0) {
        //printf("[OSPF] Thread creation failed!\n");
        verbose(1, "[OSPFInitHelloThread]:: unable to create thread.. ");
        return -1;
    }
    //printf("[OSPF] Thread created!\n");
    return handlers.hello_thread;
}

void *OSPFCheckDead(void* ptr) {
    int i,j,k;
    uchar network[4];
    char tmpbuf[MAX_TMPBUF_LEN];
    while (1) {
        pthread_testcancel();
        //printf("Start to check dead\n");
        for (i = 0; i < MAX_INTERFACES; i++) {
            if (neigharray.neighbors[i].isalive) {
                if (neigharray.neighbors[i].isStub == FALSE) {
                    time_t time_current;
                    time_t time_neighbour = neigharray.neighbors[i].timestamp;
                    int v;

                    time(&time_current);
                    v = time_current - time_neighbour;

                    if (v > 20) {
                        printf("Diff %d\n", v);
                        printf("Dead interface %d, IP %s\n", i, IP2Dot(tmpbuf, netarray.elem[neigharray.neighbors[i].interface_id]->ip_addr));
                        printf("Delete route by interface\n");
                        deleteRouteEntryByInterface(route_tbl, neigharray.neighbors[i].interface_id);
                        neigharray.neighbors[i].isalive = FALSE;
                        neigharray.count--;
                        
                        //pthread_cancel(handlers.lsa_thread);
                        
                        //OSPFInitLSAThread();
                        
                    }

                }
            }
        }
        
        //check unsupported network
        for(i=0;i<MAX_ROUTES;i++){
            if(route_tbl[i].is_empty==FALSE){
                bool isFound=FALSE;
                COPY_IP(network,route_tbl[i].network);
                for(j=0;j<MAX_ROUTER_NUMBER;j++){
                    if(routerarray.routers[j].isempty==FALSE){
                        for(k=0;k<routerarray.routers[j].entryCount;k++){
                            if(COMPARE_IP(network,routerarray.routers[j].entries[k].network)){
                                isFound=TRUE;
                            }
                        }
                    }
                }
                if(isFound==FALSE){
                    printf("delete route %d\n",i);
                    deleteRouteEntryByIndex(route_tbl, i);
                }
            }
        }
        
        sleep(10);
    }
}

int OSPFInitCheckDeadThread() {
    int threadstat, threadid;
    threadstat = pthread_create((pthread_t *) & handlers.dead_thread, NULL, (void *) OSPFCheckDead, NULL);
    //printf("[OSPF] Thread creating!\n");
    if (threadstat != 0) {
        //printf("[OSPF] Thread creation failed!\n");
        verbose(1, "[OSPFInitHelloThread]:: unable to create thread.. ");
        return -1;
    }
    //printf("[OSPF] Thread created!\n");
    return handlers.dead_thread;
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
            //printf("OSPFSendLSA: 1\n");
            lsa_data->allZeors = 0;
            lsa_data->numberOfLinks = neigharray.count;
            for (j = 0; j < MAX_INTERFACES; j++) {
                //printf("OSPFSendLSA: 2\n");
                if (neigharray.neighbors[j].isalive) {
                    //printf("OSPFSendLSA: 3\n");

                    for (k = 0; k < 5; k++)
                        lsa_data->elem[neighCounter].allZeros[k] = 0;
                    //printf("OSPFSendLSA: 5\n");
                    lsa_data->elem[neighCounter].metrics = 1;
                    //printf("neighbors netmask %s\n", IP2Dot(tmpbuf, neigharray.neighbors[j].netmask));
                    //printf("neighbors routeraddress %s\n", IP2Dot(tmpbuf, netarray.elem[neigharray.neighbors[j].interface_id]->ip_addr));
                    if (neigharray.neighbors[j].isStub) {
                        for (k = 0; k < 4; k++)
                            network[k] = neigharray.neighbors[j].netmask[k] & netarray.elem[neigharray.neighbors[j].interface_id]->ip_addr[k];
                        //printf("OSPFSendLSA: 4\n");
                        COPY_IP(lsa_data->elem[neighCounter].linkID, gHtonl(tmpbuf, network));
                        COPY_IP(lsa_data->elem[neighCounter].linkData, gHtonl(tmpbuf, neigharray.neighbors[j].netmask));
                        lsa_data->elem[neighCounter].linkType = STUB;
                    } else {
                        for (k = 0; k < 4; k++)
                            network[k] = neigharray.neighbors[j].netmask[k] & neigharray.neighbors[j].ip[k];
                        //printf("OSPFSendLSA: 4\n");
                        COPY_IP(lsa_data->elem[neighCounter].linkID, gHtonl(tmpbuf, network));
                        COPY_IP(lsa_data->elem[neighCounter].linkData, gHtonl(tmpbuf, netarray.elem[neigharray.neighbors[j].interface_id]->ip_addr));
                        lsa_data->elem[neighCounter].linkType = ANY_TO_ANY;
                    }
                    //printf("OSPFSendLSA: 6\n");
                    neighCounter++;
                }
            }
            //printf("OSPFSendLSA: 7\n");
            //Fill in the lsa_header
            lsa_header->age = 0;
            lsa_header->type = 1;
            COPY_IP(lsa_header->linkstateid, gHtonl(tmpbuf, netarray.elem[neigharray.neighbors[i].interface_id]->ip_addr));
            COPY_IP(lsa_header->adrouter, gHtonl(tmpbuf, netarray.elem[neigharray.neighbors[i].interface_id]->ip_addr));
            lsa_header->seq = seq;
            lsa_header->checksum = 0;
            lsa_header->len = sizeof (ospf_lsa_header_t) + sizeof (lsa_data_t)-(MAX_INTERFACES - neighCounter) * sizeof (lsa_elem_t);

            //printf("OSPFSendLSA: 8\n");
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

            //printf("Sending %d\n", i);

            //printf("IP packet: version %d\n", ip_pkt->ip_version);
            //printf("OSPF packet: version %d Source IP %u.%u.%u.%u\n", ospf_pkt->version, ospf_pkt->ip_src[0], ospf_pkt->ip_src[1], ospf_pkt->ip_src[2], ospf_pkt->ip_src[3]);
            //printf("LSA data: Number of Links %d \n", lsa_data->numberOfLinks);

            IPSend2Output(pkt);
        }
    }
    seq++;

}

void *OSPFRunLSA(void* ptr) {
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    while (1) {
        pthread_testcancel();
        OSPFSendLSAMessage();
        pthread_testcancel();
        sleep(15);
    }
}

int OSPFInitLSAThread() {
    int threadstat;

    threadstat = pthread_create((pthread_t *) & handlers.lsa_thread, NULL, (void *) OSPFRunLSA, NULL);
    //printf("[OSPF] Thread creating!\n");
    if (threadstat != 0) {
        //printf("[OSPF] Thread creation failed!\n");
        verbose(1, "[OSPFInitLSAThread]:: unable to create thread.. ");
        return -1;
    }
    //printf("[OSPF] Thread created!\n");
    return handlers.lsa_thread;
}

void OSPFPacketProcess(gpacket_t* in_packet) {
    int hello_neighbors_size = 0;
    int i = 0;
    int j = 0;
    char tmpbuf[MAX_TMPBUF_LEN];
    ip_packet_t *ip_pkt = (ip_packet_t*) (in_packet->data.data);
    ospf_header_t* ospf_pkt = (ospf_header_t*) (ip_pkt + 1);

    //printf("IP packet: version %d\n", ip_pkt->ip_version);
    //printf("OSPF packet: version %d Source IP %u.%u.%u.%u\n", ospf_pkt->version, ospf_pkt->ip_src[0], ospf_pkt->ip_src[1], ospf_pkt->ip_src[2], ospf_pkt->ip_src[3]);

    if (ospf_pkt->type == 1) {

        ospf_hello_data_t* hello_data = (ospf_hello_data_t*) (ospf_pkt + 1);
        //printf("Hello data: Hello Interval %d \n", hello_data->helloInterval);
        hello_neighbors_size = MAX_INTERFACES - (sizeof (ospf_header_t) + sizeof (ospf_hello_data_t) - ospf_pkt->msglen) / sizeof (neigh_ip_t);

        for (i = 0; i < hello_neighbors_size; i++) {
            //printf("Hello data neighbors %d: %u.%u.%u.%u\n", i + 1, hello_data->neighbors[i].ip[0], hello_data->neighbors[i].ip[1], hello_data->neighbors[i].ip[2], hello_data->neighbors[i].ip[3]);
        }

        if (hello_updateTheNeighbors(in_packet)) {
            //do something
            //recalculate the algorithm
            //initiate LSA message to neighbor.
            OSPFSendLSAMessage();
            //printf("Need update!");
        }

    } else if (ospf_pkt->type == 4) {
        ospf_lsa_header_t* lsa_header = (ospf_lsa_header_t*) (ospf_pkt + 1);
        lsa_data_t* lsa_data = (lsa_data_t*) (lsa_header + 1);

        //forward or not
        if (updateRouterArray(lsa_header)) {
            //forward
            for (i = 0; i < MAX_INTERFACES; i++) {
                if (neigharray.neighbors[i].isalive && neigharray.neighbors[i].interface_id != in_packet->frame.src_interface) {
                    gpacket_t* gpkt = malloc(sizeof (gpacket_t));
                    memcpy(gpkt, in_packet, sizeof (gpacket_t));
                    //printf("Interface %d:%d\n", i, netarray.elem[i]->interface_id);
                    encapsulationForOSPF(gpkt, netarray.elem[i]);
                    //RouteTableInit(route_tbl);
                    generateRoutingTable();
                    IPSend2Output(gpkt);
                }
            }
        }

        //printf("LSA header link state id %s\n", IP2Dot(tmpbuf, lsa_header->linkstateid));
        //printf("LSA data number of links: %d\n", lsa_data->numberOfLinks);
        //printf("LSA data first element ip:%s\n", IP2Dot(tmpbuf + 20, lsa_data->elem[0].linkID));
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
    //printf("updateRouterArray 1\n");
    for (i = 0; i < MAX_ROUTER_NUMBER; i++) {
        if (!routerarray.routers[i].isempty) {
            //printf("updateRouterArray 2\n");
            router = &(routerarray.routers[i]);
            for (j = 0; j < router->entryCount; j++) {
                //printf("Router->entries[j] %s\n", IP2Dot(tmpbuf, router->entries[j].linkdata.routerAddress));
                //printf("lsa_header->adrouter %s\n", IP2Dot(tmpbuf, adRouterIP));
                if (COMPARE_IP(router->entries[j].linkdata.routerAddress, adRouterIP) == 0) {
                    //printf("updateRouterArray 3\n");
                    isFound = TRUE;
                    if (router->seq < lsa_header->seq) {
                        //printf("updateRouterArray 4\n");
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
            //printf("updateRouterArray 5\n");
            if (isFound == TRUE) {
                return !duplicated;
            }
        }
    }
    //printf("updateRouterArray 6\n");
    if (isFound == FALSE) {
        //printf("updateRouterArray 7\n");
        for (i = 0; i < MAX_ROUTER_NUMBER; i++) {
            if (routerarray.routers[i].isempty) {
                //printf("updateRouterArray 8\n");
                router = &(routerarray.routers[i]);
                duplicated = FALSE;
                router->seq = lsa_header->seq;
                //printf("seq:%d\n", lsa_header->seq);
                router->entryCount = lsa_data->numberOfLinks;
                //printf("Number of Links:%d\n", lsa_data->numberOfLinks);
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
                routerarray.count++;
                break;
            }
        }
    }
    //printf("updateRouterArray 9\n");
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
    COPY_IP(netmask, gNtohl(tmpbuf, hello_data->netmask));
    //printf("Hello:original %s\n", IP2Dot(tmpbuf, neigharray.neighbors[interface_id].ip));
    //printf("Hello:pkt_ip %s\n", IP2Dot(tmpbuf, pkt_ip));
    //printf("Hello:IP changed %s->%s\n",IP2Dot(tmpbuf,neigharray.neighbors[interface_id].ip),IP2Dot(tmpbuf,pkt_ip));
    //printf("Hello:Compare:%d\n", COMPARE_IP(neigharray.neighbors[interface_id].ip, pkt_ip));
    if (COMPARE_IP(neigharray.neighbors[interface_id].ip, pkt_ip) != 0) {
        //printf("Hello:IP changed %s->%s\n", IP2Dot(tmpbuf, neigharray.neighbors[interface_id].ip), IP2Dot(tmpbuf + 20, pkt_ip));
        COPY_IP(neigharray.neighbors[interface_id].ip, pkt_ip);
        update = TRUE;
    }

    if (COMPARE_IP(neigharray.neighbors[interface_id].netmask, netmask) != 0) {
        //printf("Hello:Netmask changed %s->%s\n", IP2Dot(tmpbuf, neigharray.neighbors[interface_id].netmask), IP2Dot(tmpbuf + 20, netmask));
        COPY_IP(neigharray.neighbors[interface_id].netmask, netmask);
        update = TRUE;
    }

    if (COMPARE_IP(neigharray.neighbors[interface_id].designatedIP, designatedIP) != 0) {
        //printf("Hello:DesignatedIP changed %s->%s\n", IP2Dot(tmpbuf, neigharray.neighbors[interface_id].designatedIP), IP2Dot(tmpbuf + 20, designatedIP));
        COPY_IP(neigharray.neighbors[interface_id].designatedIP, designatedIP);
        update = TRUE;
    }

    if (COMPARE_IP(neigharray.neighbors[interface_id].backupdesignatedIP, backupdesignatedIP) != 0) {
        //printf("Hello:BackupDesignatedIP changed %s->%s\n", IP2Dot(tmpbuf, neigharray.neighbors[interface_id].backupdesignatedIP), IP2Dot(tmpbuf + 20, backupdesignatedIP));
        COPY_IP(neigharray.neighbors[interface_id].backupdesignatedIP, backupdesignatedIP);
        update = TRUE;
    }

    if (helloInterval != neigharray.neighbors[interface_id].helloInterval) {
        //printf("Hello:HelloInterval changed %d->%d\n", neigharray.neighbors[interface_id].helloInterval, helloInterval);
        neigharray.neighbors[interface_id].helloInterval = helloInterval;
        update = TRUE;
    }

    if (deadInterval != neigharray.neighbors[interface_id].deadInterval) {
        //printf("Hello:DeadInterval changed %d->%d\n", neigharray.neighbors[interface_id].deadInterval, deadInterval);
        neigharray.neighbors[interface_id].deadInterval = deadInterval;
        update = TRUE;
    }

    if (interface_id != neigharray.neighbors[interface_id].interface_id) {
        neigharray.neighbors[interface_id].interface_id = interface_id;
        update = TRUE;
    }

    if (neigharray.neighbors[interface_id].isalive == FALSE) {
        neigharray.count++;
        neigharray.neighbors[interface_id].isalive = TRUE;
        update = TRUE;
    }
    time(&(neigharray.neighbors[interface_id].timestamp));
    //the rest of the properties are not very important, we ignored here.
    return update;
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
    //printf("encapsulation: dst_interface: %d\n", pkt->frame.dst_interface);
    //jingsi: set ip_src to the IP address of current interface IP.
    //printf("encapsulation: %s\n", IP2Dot(tmpbuf, interf->ip_addr));
    COPY_IP(ip_pkt->ip_src, gHtonl(tmpbuf, interf->ip_addr));
    //printf("encapsulation: %s\n", IP2Dot(tmpbuf, ip_pkt->ip_src));
    //jingsi: dest_ip is the broadcast IP
    COPY_IP(ip_pkt->ip_dst, gHtonl(tmpbuf, dst_ip));

    //jingsi:  frame.nxth_ip_addr is destination interface IP address
    COPY_IP(pkt->frame.nxth_ip_addr, gHtonl(tmpbuf, dst_ip));
    //xuepeng: an alternative method to bypass the ARP resolution.            
    pkt->frame.arp_valid = FALSE;
    pkt->frame.arp_bcast = TRUE;
    COPY_MAC(pkt->data.header.dst, mac_addr);

    //printf("%s\n", IP2Dot(tmpbuf, ip_pkt->ip_dst));
    ip_pkt->ip_prot = OSPF_PROTOCOL;

    //compute the new checksum
    cksum = checksum((uchar *) ip_pkt, ip_pkt->ip_hdr_len * 2);
    //printf("Checksum %d\n", cksum);
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

void OSPFViewNeighbors() {
    int i;
    char tmpbuf[MAX_TMPBUF_LEN];
    printf("Neighbors count:%d\n", neigharray.count);
    for (i = 0; i < MAX_INTERFACES; i++) {
        if (neigharray.neighbors[i].isalive) {
            printf("Neighbor %d information: IP %s\n", i, IP2Dot(tmpbuf, neigharray.neighbors[i].ip));
        }
    }
}

void handleUML(gpacket_t* pkt) {
    int k;
    char tmpbuf[MAX_TMPBUF_LEN];
    uchar netmask[4] = DEFAULT_NETMASK;

    int interface_id = pkt->frame.src_interface;
    ip_packet_t* ip_pkt = (ip_packet_t*) pkt->data.data;
    COPY_IP(neigharray.neighbors[interface_id].ip, gNtohl(tmpbuf, ip_pkt->ip_src));
    COPY_IP(neigharray.neighbors[interface_id].netmask, netmask);
    //printf("HandleUML,%s\n", IP2Dot(tmpbuf, netmask));
    neigharray.neighbors[interface_id].interface_id = interface_id;
    neigharray.neighbors[interface_id].isStub = TRUE;
    if (neigharray.neighbors[interface_id].isalive == FALSE) {
        neigharray.neighbors[interface_id].isalive = TRUE;
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
//void djAlg(int** cost, int** next, int size) {
//    int v0 = 0;
//    int isFinal[MAX_ROUTER_NUMBER], isFirstHop[MAX_ROUTER_NUMBER];
//    int dist[MAX_ROUTER_NUMBER];
//    int i, v, w, min, k;
//    int shortestDistance[MAX_ROUTER_NUMBER][MAX_ROUTER_NUMBER];
//    printf("\nshortest path:\n");
//    for (k = 0; k < size; k++) {
//        // initial shortest path(not the result)          
//        for (v = 0; v < size; v++) {
//            isFinal[v] = 0;
//            isFirstHop[v] = TRUE;
//            next[k][v] = v;
//            dist[v] = cost[v0][v];
//        }
//        // dis(v0-v0)=0   is the final distance         
//        isFinal[v0] = TRUE;
//        // vo - the other points:
//        for (i = 0; i < size - 1; i++) {
//            //initial shortest path = inf
//            min = 999;
//            // looking for shortest path         
//            for (w = 0; w < size; w++) {
//                if (!isFinal[w] && dist[w] < min) {
//                    min = dist[w];
//                    //v: current considered destination
//                    v = w;
//                }
//            }
//            isFinal[v] = 1;
//
//            // add new path  
//            for (w = 0; w < size; w++) {
//                // update distance matrix           
//                if (!isFinal[w] && dist[v] + cost[v][w] < dist[w]) {
//                    if (isFirstHop[w] == TRUE) {
//                        next[v0][w] = v;
//                        isFirstHop[w] = FALSE;
//                    }
//                    dist[w] = dist[v] + cost[v][w];
//                }
//            }
//        }
//
//        for (i = 0; i < size; i++) {
//            //shortestDistance[v0][i] = dist[i];
//            //printf("%d->%d: %2d\t", v0, i, dist[i]);
//            //printf("%d->%d:%2d next hop is: %d||", v0, i, shortestDistance[v0][i],next[v0][i]);
//            cost[v0][i] = dist[i];
//        }
//        //printf("\n");
//        //next source point:
//        v0++;
//    }
//}

void djAlg(int** c, int** v, int size) {
    int ref, x, y, i, j;

    for (ref = 0; ref < size; ref++) {
        for (x = 0; x < size; x++) {
            if (x == ref)
                continue;

            for (y = 0; y < size; y++) {
                if (y == ref)
                    continue;

                if (c[ref][y] + c[x][ref] < c[x][y]) {
                    c[x][y] = c[ref][y] + c[x][ref];
                    v[x][y] = ref;
                }

            }
        }
    }
}

void generateRoutingTable() {
    int routercount = 0;
    int k, i, j;
    int topSize = routerarray.count + 1;
    int routerIndex[topSize];
    int** relation = (int**) malloc(topSize * sizeof (int*));
    int** via = (int**) malloc(topSize * sizeof (int*));
    
    uchar network[4];
    uchar netmask[4];
    uchar nexthop[4];
    uchar allzeros[4] = ALLZEROS;
    int interface_id;
    char tmpbuf[MAX_TMPBUF_LEN];
    //int** c,v;
    
    rtcarray->count=0;
    for (i = 0; i < topSize; i++) {
        *(relation + i) = malloc(topSize * sizeof (int));
        *(via + i) = malloc(topSize * sizeof (int));
    }


    //for source router
    int networkCount = 0;
    uchar networks[MAX_INTERFACES][4];

    //printf("1 %d\n", topSize);

    for (i = 0; i < topSize; i++) {
        for (j = 0; j < topSize; j++) {
            relation[i][j] = INIF;
            via[i][j] = -1;
        }
    }
    for (i = 0; i < topSize; i++) {
        relation[i][i] = 0;
        via[i][i] = i;
    }

    //put the source router in the first position.
    routerIndex[routercount++] = -1;
    //put the index of the rest router into the array.
    for (i = 0; i < MAX_ROUTER_NUMBER; i++) {
        if (routerarray.routers[i].isempty == FALSE) {
            routerIndex[routercount++] = i;
        }
    }
    //printf("2\n");
    //establish the relation between router
    //check the source router first.

    //found out the network addresses which directly connected to the source router
    for (i = 0; i < MAX_INTERFACES; i++) {
        if (neigharray.neighbors[i].isalive) {
            for (k = 0; k < 4; k++)
                network[k] = neigharray.neighbors[i].netmask[k] & netarray.elem[neigharray.neighbors[i].interface_id]->ip_addr[k];
        }
        COPY_IP(networks[networkCount++], network);
    }
    for (i = 0; i < networkCount; i++) {
        for (j = 1; j < routercount; j++) {
            router_t r = routerarray.routers[routerIndex[j]];
            for (k = 0; k < r.entryCount; k++) {
                if (COMPARE_IP(networks[i], r.entries[k].network) == 0) {
                    relation[0][j] = 1;
                    relation[j][0] = 1;
                    via[0][j] = j;
                    via[j][0] = 0;
                }
            }
        }
    }

    //printf("3\n");
    
    for (i = 1; i < routercount; i++) {
        for (j = i + 1; j < routercount; j++) {
            router_t* a = &(routerarray.routers[routerIndex[i]]);
            router_t* b = &(routerarray.routers[routerIndex[j]]);
            if (AreRoutersConnected(a, b) != NULL) {
                relation[i][j] = 1;
                relation[j][i] = 1;
                via[i][j] = j;
                via[j][i] = i;
            }
        }
    }

    //printf("4\n");
    
    djAlg(relation, via, topSize);

    //printf("5\n");
    
    //for self
    for (i = 0; i < MAX_INTERFACES; i++) {
        if (neigharray.neighbors[i].isalive) {
            bool isFound = FALSE;
            COPY_IP(netmask, neigharray.neighbors[i].netmask);
            interface_id = neigharray.neighbors[i].interface_id;


            for (j = 0; j < 4; j++)
                network[j] = netmask[j] & netarray.elem[interface_id]->ip_addr[j];

            COPY_IP(nexthop, allzeros);

            
            
            for (k = 0; k < rtcarray->count; k++) {
                //printf("Comparing %s\n", IP2Dot(tmpbuf, router->entries[j].network));
                if (COMPARE_IP(network, rtcarray->rtc[k].network) == 0) {
                    if (relation[0][i] < rtcarray->rtc[k].cost) {

                        COPY_IP(rtcarray->rtc[rtcarray->count].netmask, netmask);
                        COPY_IP(rtcarray->rtc[rtcarray->count].network, network);
                        COPY_IP(rtcarray->rtc[rtcarray->count].nexthop, nexthop);
                        rtcarray->rtc[rtcarray->count].interface_id = interface_id;
                        rtcarray->rtc[k].cost = 0;

                    }
                    isFound = TRUE;
                    break;
                }
            }
            if(isFound==FALSE){
                rtcarray->rtc[rtcarray->count].interface_id = interface_id;
                COPY_IP(rtcarray->rtc[rtcarray->count].netmask, netmask);
                COPY_IP(rtcarray->rtc[rtcarray->count].network, network);
                COPY_IP(rtcarray->rtc[rtcarray->count].nexthop, nexthop);
                rtcarray->rtc[rtcarray->count].cost = 0;
                rtcarray->count++;
            }
        }
    }

    //printf("6\n");
    
    //for others
    for (i = 1; i < topSize; i++) {
        router_t* router = routerarray.routers + routerIndex[i];

        //printf("6.1\n");
        
        int nextHopIndex = via[0][i];
        int nextHopInterface;
        //isolated router
        if (nextHopIndex == -1) {
            printf("-1 found\n");
            routerarray.routers[routerIndex[i]].isempty = TRUE;
            routerarray.count--;
            continue;
        }
        
        //printf("6.2\n");
        
        while (via[nextHopIndex][0] != 0) {
            nextHopIndex = via[nextHopIndex][0];
            if (nextHopIndex == -1) {
                printf("-1 found in loop\n");
                routerarray.routers[routerIndex[i]].isempty = TRUE;
                routerarray.count--;
                break;
            }
        }
        
        for(j=0;j<topSize;j++){
            printf("\n");
            for(k=0;k<topSize;k++){
                printf("%d ",via[j][k]);
            }
        }
        printf("\n");
        
        if(nextHopIndex==-1){
            continue;
        }

        //printf("6.3\n");
        
        router_t* nextRouter;
        uchar nextNetwork[4];

        nextRouter = &(routerarray.routers[routerIndex[nextHopIndex]]);
        nextHopInterface = isRouterConnectedToMe(nextRouter);

        if (nextHopInterface == -1) {
            routerarray.routers[routerIndex[i]].isempty = TRUE;
            routerarray.count--;
            continue;
        }

        //printf("6.4\n");
        
        interface_id = nextHopInterface;

        COPY_IP(netmask, neigharray.neighbors[interface_id].netmask);
        
        COPY_IP(nexthop, neigharray.neighbors[interface_id].ip);

        //printf("6.5\n");
        
        for (j = 0; j < router->entryCount; j++) {
            bool isFound = FALSE;
            for (k = 0; k < rtcarray->count; k++) {
                if (COMPARE_IP(router->entries[j].network, rtcarray->rtc[k].network) == 0) {
                    if (relation[0][i] < rtcarray->rtc[k].cost) {

                        COPY_IP(rtcarray->rtc[rtcarray->count].netmask, netmask);
                        COPY_IP(rtcarray->rtc[rtcarray->count].network, router->entries[j].network);
                        COPY_IP(rtcarray->rtc[rtcarray->count].nexthop, nexthop);
                        rtcarray->rtc[rtcarray->count].interface_id = interface_id;
                        rtcarray->rtc[k].cost = relation[0][i];

                    }
                    isFound = TRUE;
                    break;

                }
            }
            
            //printf("6.6\n");
            
            if (isFound == TRUE) {
                continue;
            } else {
                rtcarray->rtc[rtcarray->count].interface_id = interface_id;
                COPY_IP(rtcarray->rtc[rtcarray->count].netmask, netmask);
                COPY_IP(rtcarray->rtc[rtcarray->count].network, router->entries[j].network);
                COPY_IP(rtcarray->rtc[rtcarray->count].nexthop, nexthop);
                rtcarray->rtc[rtcarray->count].cost = relation[0][i];
                rtcarray->count++;
            }
        }

        
        //printf("6.7\n");
        
    }
    
    //printf("7\n");
    
    for (i = 0; i < rtcarray->count; i++){
        addRouteEntry(route_tbl, rtcarray->rtc[i].network, rtcarray->rtc[i].netmask, rtcarray->rtc[i].nexthop, rtcarray->rtc[i].interface_id);
    }
    
    //sleep(1);
//    {
//        int i, rcount = 0;
//        char tmpbuf[MAX_TMPBUF_LEN];
//        interface_t *iface;
//
//        //printf("\n=================================================================\n");
//        //printf("      R O U T E  T A B L E \n");
//        //printf("-----------------------------------------------------------------\n");
//        //printf("Index\tNetwork\t\tNetmask\t\tNexthop\t\tInterface \n");
//
//        for (i = 0; i < rtcarray->count; i++){
//            iface = findInterface(rtcarray->rtc[i].interface_id);
//            printf("[%d]\t%s\t%s\t%s\t\t%s\n", i, IP2Dot(tmpbuf, rtcarray->rtc[i].network),
//                    IP2Dot((tmpbuf + 20), rtcarray->rtc[i].netmask), IP2Dot((tmpbuf + 40), rtcarray->rtc[i].nexthop), iface->device_name);
//            rcount++;
//        }
//        //printf("-----------------------------------------------------------------\n");
//        //printf("      %d number of routes found. \n", rcount);
//    }
    
    //printf("8\n");
    
    for (i = 0; i < topSize; i++) {
        free(*(relation + i));
        free(*(via + i));
    }

    free(relation);
    free(via);
    
    //printf("9\n");
}

uchar* AreRoutersConnected(router_t* a, router_t* b) {
    int i, j;
    char tmpbuf[MAX_TMPBUF_LEN];
    for (i = 0; i < a->entryCount; i++) {
        for (j = 0; j < a->entryCount; j++) {
            if (COMPARE_IP(a->entries[i].network, b->entries[j].network) == 0) {
                //printf("a %s, b %s\n", IP2Dot(tmpbuf, a->entries[i].network), IP2Dot(tmpbuf + 20, b->entries[j].network));
                //printf("a and b are related!\n");
                return a->entries[i].network;
            }
        }

    }
    return NULL;
}

int isRouterConnectedToMe(router_t* a) {
    int i, j;
    char tmpbuf[MAX_TMPBUF_LEN];
    uchar network[4];
    for (i = 0; i < MAX_INTERFACES; i++) {
        if (neigharray.neighbors[i].isalive) {
            for (j = 0; j < 4; j++)
                network[j] = neigharray.neighbors[i].netmask[j] & netarray.elem[neigharray.neighbors[i].interface_id]->ip_addr[j];
            for (j = 0; j < a->entryCount; j++) {
                if (COMPARE_IP(a->entries[j].network, network) == 0) {
                    //printf("a %s\n", IP2Dot(tmpbuf, a->entries[j].network));
                    //printf("a is related!\n");
                    return neigharray.neighbors[i].interface_id;
                }
            }
        }
    }
    return -1;
}
