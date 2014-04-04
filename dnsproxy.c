#include "dnsproxy.h"

void process_query(SOCKET server, char* buffer, int size, struct sockaddr_in *source)
{
	int i, len;
	DNS_HDR *hdr, *rhdr;
	char *pos, *rear;
	char domain[PACKAGE_SIZE];
	char rbuffer[PACKAGE_SIZE];

	hdr = (DNS_HDR*)buffer;
	rhdr = (DNS_HDR*)rbuffer;
	memset(rbuffer, 0, PACKAGE_SIZE);
	rhdr->id = hdr->id;
	rhdr->qr = 1;
	// check header format
	if(hdr->qr != 0 || hdr->tc != 0 || ntohs(hdr->q_count) != 1)
		rhdr->rcode = 1;
	else {
		// analize query section
		pos = buffer + sizeof(DNS_HDR);
		rear = buffer + size;
		i = 0;
		memset(domain, 0, PACKAGE_SIZE);
		while(pos < rear) {
			len = (int)*pos++;
			if(len < 0 || len > 63 || (pos + len) > (rear - sizeof(DNS_QES))) {
				rhdr->rcode = 1;
				break;
			}
			if(len > 0) {
				if(i > 0)
					domain[i++] = '.';
				memcpy(domain + i, pos, len);
				i+= len;
				pos += len;
			}
			else {
				DNS_QES *qes = (DNS_QES*) pos;
				if(ntohs(qes->classes) != 0x01)
					rhdr->rcode = 4;
				else
					pos += sizeof(DNS_QES);
				break;
			}
		}
	}
	if(rhdr->rcode != 0) {
		sendto(server, rbuffer, sizeof(DNS_HDR), 0, (struct sockaddr*)source, sizeof(struct sockaddr_in));
		return;
	}
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
