#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>

#if defined(_MSC_VER)
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"mswsock")
#endif

#define BUFFER_SIZE 16384

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

typedef struct cached_node {
	struct cached_node* prev;
	struct cached_node* next;
	unsigned int id;
	unsigned short orgin;
	struct sockaddr_in address;
} CACHE_NODE;

int dnsproxy(unsigned int local_port, const char* remote_addr, unsigned int remote_port)
{
	int fds;
	SOCKET server;
	fd_set readfds;
	struct sockaddr_in addr;
	char buffer[BUFFER_SIZE];

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
			DNS_HDR* hdr;
			int addrlen = sizeof(addr);
			int buflen = recvfrom(server, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&addr, &addrlen);
			if(buflen < sizeof(DNS_HDR))
				return;
			hdr = (DNS_HDR*)buffer;
			printf("id: %d\n", ntohs(hdr->id));
		}
	}
	return 0;
}

int main(int argc, char* argv[])
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2,2), &wsaData);
	return dnsproxy(53, "8.8.8.8", 53);
}
