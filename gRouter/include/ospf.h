/*
 * ospf.h (header file for Open Shortest Path First (OSPF))
 * AUTHOR: Originally written by Xuepeng Xu
 * DATE: Nov.1st 2013
 *
 */
#ifndef __OSPF_H
#define __OSPF_H

#include "ip.h"

void *OSPFSendHelloMessage(void* ptr);
int OSPFInitHelloThread();

#endif