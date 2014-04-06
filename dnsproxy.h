/*
 * Copyright 2014, Vietor Liu <vietor.liu at gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version. For full terms that can be
 * found in the LICENSE file.
 */

#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"
#include "rbtree.h"
#include "xgetopt.h"

#if defined(_MSC_VER)
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"mswsock")
#endif

typedef struct {
	unsigned short id;       // identification number
	unsigned char rd :1;     // recursion desired
	unsigned char tc :1;     // truncated message
	unsigned char aa :1;     // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1;     // query/response flag
	unsigned char rcode :4;  // response code
	unsigned char cd :1;     // checking disabled
	unsigned char ad :1;     // authenticated data
	unsigned char z :1;      // its z! reserved
	unsigned char ra :1;     // recursion available
	unsigned short q_count;  // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
} DNS_HDR;

typedef struct {
	unsigned short type;
	unsigned short classes;
} DNS_QES;

typedef struct {
	struct rbnode rb_name;
	struct in_addr addr;
	char domain[1];
} DOMAIN_CACHE;

void domain_cache_init(const char* file);
DOMAIN_CACHE* domain_cache_search(char* domain);

typedef struct {
	struct rbnode rb_new;
	struct rbnode rb_expire;
	time_t expire;
	unsigned short new_id;
	unsigned short old_id;
	struct sockaddr_in address;
} PROXY_CACHE;

void proxy_cache_init(unsigned short timeout);
PROXY_CACHE* proxy_cache_search(unsigned short new_id);
PROXY_CACHE* proxy_cache_insert(unsigned short old_id, struct sockaddr_in *address);
void proxy_cache_delete(PROXY_CACHE *cache);
void proxy_cache_clean();
