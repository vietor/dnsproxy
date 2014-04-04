
#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include "rbtree.h"

#if defined(_MSC_VER)
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"mswsock")
#endif

#define PACKAGE_SIZE 512

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
	int ttl;
	struct in_addr addr;
	char domain[1];
} DOMAIN_CACHE;

typedef struct proxy_node {
	struct rbnode rb_by_name;
	unsigned int id;
	unsigned short orgin;
	struct sockaddr_in address;
} PROXY_NODE;

void domain_cache_init();
DOMAIN_CACHE* domain_cache_search(char* domain);
