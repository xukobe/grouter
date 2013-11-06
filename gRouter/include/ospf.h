/*
 * ospf.h (header file for Open Shortest Path First (OSPF))
 * AUTHOR: Originally written by Xuepeng Xu
 * DATE: Nov.1st 2013
 *
 */
#ifndef __OSPF_H
#define __OSPF_H

#include "ip.h"
#include "gnet.h"
#include "message.h"
#include <time.h>

#define MAX_ROUTER_NUMBER 50
#define DEFAULT_HELLO_INTERVAL 10
#define DEFAULT_DEAD_INTERVAL 40
#define DEFAULT_PRIORITY 0
#define DEFAULT_NETMASK {0x00, 0xFF, 0xFF, 0xFF}
#define DEFAULT_DESIGNATED_ROUTER_IP {0x00, 0x00, 0x00, 0x00}
#define DEFAULT_BACKUP_DESIGNATED_ROUTER_IP {0x00, 0x00, 0x00, 0x00}
#define ANY_TO_ANY 2
#define STUB 3
#define INIF 100
#define ALLZEROS {0x00, 0x00, 0x00, 0x00}

//ospf header
typedef struct _ospf_header_t{
    uint8_t version;
    uint8_t type;
    uint16_t msglen;
    uchar ip_src[4];
    uint32_t areaID;
    uint16_t checksum;
    uint16_t authtype;
    //uchar auth[8];
} ospf_header_t;

//ospf lsa
typedef struct _ospf_lsa_header_t{
    uint16_t age;
    uint16_t type;
    uchar linkstateid[4];
    uchar adrouter[4];
    uint32_t seq;
    uint16_t checksum;
    uint16_t len;
}ospf_lsa_header_t;

typedef struct _lsa_elem_t{
    uchar linkID[4];
    uchar linkData[4];
    uint8_t linkType;
    uint8_t allZeros[5];
    uint16_t metrics;
}lsa_elem_t;

typedef struct _lsa_data_t{
    uint16_t allZeors;
    uint16_t numberOfLinks;
    lsa_elem_t elem[MAX_INTERFACES];
}lsa_data_t;

//ospf hello
typedef struct _neigh_ip_t{
    uchar ip[4];
}neigh_ip_t;

typedef struct _ospf_hello_data_t{
    uchar netmask[4];
    uint16_t helloInterval;
    uint8_t options;
    uint8_t priority;
    uint32_t deadInterval;
    uchar designatedIP[4];
    uchar backupdesignatedIP[4];
    neigh_ip_t neighbors[MAX_INTERFACES];
}ospf_hello_data_t;

//neighbor entry
typedef struct _neigh_entry_t{
    uchar ip[4];
    uchar netmask[4];
    time_t timestamp;//keep the time stamp for the last hello message
    uint16_t helloInterval;
    uint32_t deadInterval;
    uchar designatedIP[4];
    uchar backupdesignatedIP[4];
    int interface_id;
    bool isStub;
    bool isalive;
}neigh_entry_t;

typedef struct _neigh_array_t{
    neigh_entry_t neighbors[MAX_INTERFACES];
    uint16_t count;
}neigh_array_t;

//Router information
typedef struct _router_entry_t{
    uchar network[4];
    union{
        uchar routerAddress[4];
        uchar netmask[4];
    }linkdata;
    bool isStub;
}router_entry;

typedef struct _router_t{
    bool isempty;
    int entryCount;
    int seq;
    router_entry entries[MAX_INTERFACES];
}router_t;

typedef struct _router_array_t{
    int count;
    router_t routers[MAX_ROUTER_NUMBER];
}router_array;

typedef struct _route_table_cache_t{
    uchar network[4];
    uchar netmask[4];
    uchar nexthop[4];
    int interface_id;
    int cost;
}route_table_cache_t;

typedef struct _route_table_cache_array_t{
    int count;
    route_table_cache_t rtc[MAX_ROUTER_NUMBER];
}route_table_cache_array_t;

typedef struct _ospf_handler_t{
    pthread_t hello_thread;
    pthread_t lsa_thread;
    pthread_t dead_thread;
}ospf_handler_t;

int OSPFInit();

void *OSPFSendHelloMessage(void* ptr);
int OSPFInitHelloThread();

void OSPFSendLSAMessage();

int OSPFInitLSAThread();

void *OSPFRunLSA(void* ptr);

void *OSPFCheckDead(void* ptr);

int OSPFInitCheckDeadThread();

void OSPFPacketProcess(gpacket_t* in_packet);

void OSPFViewRouters();

void OSPFViewNeighbors();

bool hello_updateTheNeighbors(gpacket_t* in_packet);

bool updateRouterArray(ospf_lsa_header_t* lsa_header);

void encapsulationForOSPF(gpacket_t* pkt, interface_t* interf);

void handleUML(gpacket_t* pkt);

//100 is infinite 
void djAlg(int** c,int** v, int size);

void generateRoutingTable();

//return network address if true, else return null
uchar* AreRoutersConnected(router_t* a, router_t* b);
//return interface id, else return -1
int isRouterConnectedToMe(router_t* a);

#endif