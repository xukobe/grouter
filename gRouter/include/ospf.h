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

#define DEFAULT_HELLO_INTERVAL 10
#define DEFAULT_DEAD_INTERVAL 40

typedef struct _ospf_header_t
{
    uint8_t version;
    uint8_t type;
    uint16_t msglen;
    uchar ip_src[4], ip_dst[4];
    uint32_t areaid;
    uint16_t checksum;
    uint16_t authtype;
    uchar auth[8];
} ospf_header_t;


typedef struct _ospf_lsa_header_t
{
    uint16_t age;
    uint16_t type;
    uchar linkstateid[4];
    uchar adrouter[4];
    uint32_t seq;
    uint16_t checksum;
    uint16_t len;
}ospf_lsa_header_t;

typedef struct _neigh_ip{
    uchar ip[4];
}neigh_ip;

typedef struct _ospf_hello_data_t{
    uchar netmask[4];
    uint16_t helloInterval;
    uint8_t options;
    uint8_t priority;
    uint32_t deadInterval;
    uchar designatedIP[4];
    uchar backupdesignateIP[4];
    neigh_ip neighbors[MAX_INTERFACES];
}ospf_hello_data;

typedef struct _ospf_neigh_entry_t
{
    uchar neighbor[4];
    bool isEmpty;
    int interface_id;
    uchar neighbormask[4];
}ospf_neigh_entry;

typedef struct _ospf_neigh_array_t
{
    int count;
    ospf_neigh_entry elem[MAX_INTERFACES];
};

int OSPFInit();

void *OSPFSendHelloMessage(void* ptr);
int OSPFInitHelloThread();

void *OSPFSendLSAMessage(void* ptr);
int OSPFInitLSAThread();

void *OSPFCheckDead(void* ptr);
int OSPFInitCheckDeadThread();

#endif