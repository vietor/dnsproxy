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
} DOMAIN_CACHE_NODE;

typedef struct proxy_node {
	struct rbnode rb_by_name;
	unsigned int id;
	unsigned short orgin;
	struct sockaddr_in address;
} PROXY_NODE;

static struct {
	struct rbtree rb_name;
} domain_cache;

static int name_search(const void* k, const struct rbnode* r)
{
	DOMAIN_CACHE_NODE *right;
	right = rbtree_entry(r, DOMAIN_CACHE_NODE, rb_name);
	return strcmp((const char*) k, right->domain);
}

static int name_compare(const struct rbnode* l, const struct rbnode* r)
{
	DOMAIN_CACHE_NODE *left, *right;
	left = rbtree_entry(l, DOMAIN_CACHE_NODE, rb_name);
	right = rbtree_entry(r, DOMAIN_CACHE_NODE, rb_name);
	return strcmp(left->domain, right->domain);
}

void domain_cache_init()
{
	rbtree_init(&domain_cache.rb_name, name_search, name_compare);
}

DOMAIN_CACHE_NODE* search_domain(char* domain)
{
	struct rbnode *node;
	node = rbtree_search(&domain_cache.rb_name, domain);
	if(node == NULL)
		return NULL;
	return rbtree_entry(node, DOMAIN_CACHE_NODE, rb_name);
}

void process_query(SOCKET server, char* buffer, int size, struct sockaddr_in *source)
{
	DNS_HDR* hdr;

	hdr = (DNS_HDR*)buffer;
}

int dnsproxy(unsigned int local_port, const char* remote_addr, unsigned int remote_port)
{
	SOCKET server;
	fd_set readfds;
	struct sockaddr_in addr;
	char buffer[PACKAGE_SIZE];
	int fds, addrlen, buflen;

	server = socket(AF_INET, SOCK_DGRAM, 0);
	if(server == INVALID_SOCKET) {
		perror("create server socket");
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(local_port);
	if(bind(server, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		perror("bind server local port");
		return -1;
	}

	FD_ZERO(&readfds);
	FD_SET(server, &readfds);
	while(fds = select(0, &readfds, NULL, NULL, NULL), fds > 0) {
		if(FD_ISSET(server, &readfds)) {
			addrlen = sizeof(addr);
			buflen = recvfrom(server, buffer, PACKAGE_SIZE, 0, (struct sockaddr*)&addr, &addrlen);
			if(buflen < sizeof(DNS_HDR))
				continue;
			process_query(server, buffer, buflen, &addr);
		}
	}
	return 0;
}

int main(int argc, char* argv[])
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2,2), &wsaData);

	domain_cache_init();
	return dnsproxy(53, "8.8.8.8", 53);
}
