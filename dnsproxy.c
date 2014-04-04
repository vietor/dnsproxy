#include "dnsproxy.h"

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
