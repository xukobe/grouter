/*
 * ospf.h (header file for Open Shortest Path First (OSPF))
 * AUTHOR: Originally written by Xuepeng Xu
 * DATE: Nov.1st 2013
 *
 */
#ifndef __OSPF_H
#define __OSPF_H

#include "ip.h"


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

void *OSPFSendHelloMessage(void* ptr);
int OSPFInitHelloThread();

void *OSPFSendLSAMessage(void* ptr);
int OSPFInitLSAThread();

void *OSPFCheckDead(void* ptr);
int OSPFInitCheckDeadThread();

#endif