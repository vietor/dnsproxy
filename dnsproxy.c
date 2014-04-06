/*
 * Copyright 2014, Vietor Liu <vietor.liu at gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version. For full terms that can be
 * found in the LICENSE file.
 */

#include "dnsproxy.h"

#define VERSION "1.0.0"
#define PACKAGE_SIZE 512

typedef struct {
	SOCKET service;
	SOCKET dns_udp;
	struct sockaddr_in dns_addr;
} PROXY_ENGINE;

void process_query(PROXY_ENGINE *engine, char* buffer, int size, struct sockaddr_in *source)
{
	DNS_QES *qes, *rqes;
	DNS_HDR *hdr, *rhdr;
	PROXY_CACHE *cache;
	DOMAIN_CACHE *dcache;
	char *pos, *head, *rear;
	char domain[PACKAGE_SIZE];
	char rbuffer[PACKAGE_SIZE];
	int i, len, q_count, q_len;

	hdr = (DNS_HDR*)buffer;
	rhdr = (DNS_HDR*)rbuffer;
	memset(rbuffer, 0, PACKAGE_SIZE);

	rhdr->id = hdr->id;
	rhdr->qr = 1;
	q_len = 0;
	q_count = ntohs(hdr->q_count);
	qes = NULL;
	head = NULL;
	if(hdr->qr != 0 || hdr->tc != 0 || q_count < 1)
		rhdr->rcode = 1;
	else {
		head = buffer + sizeof(DNS_HDR);
		rear = buffer + size;
		i = 0;
		memset(domain, 0, PACKAGE_SIZE);
		pos = head;
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
				qes = (DNS_QES*) pos;
				if(ntohs(qes->classes) != 0x01)
					rhdr->rcode = 4;
				else {
					pos += sizeof(DNS_QES);
					q_len = pos - head;
				}
				break;
			}
		}
	}

	if(rhdr->rcode == 0 && q_count == 1 && ntohs(qes->type) == 0x01) {
		dcache = domain_cache_search(domain);
		if(dcache) {
			rhdr->q_count = htons(1);
			rhdr->ans_count = htons(1);
			pos = rbuffer + sizeof(DNS_HDR);
			memcpy(pos, head, q_len);
			pos += q_len;
			*pos++ = 0xc0;
			*pos++ = 0x0c;
			rqes = (DNS_QES*)pos;
			rqes->type = qes->type;
			rqes->classes = qes->classes;
			pos += sizeof(DNS_QES);
			*(unsigned int*)pos = htonl(600);
			pos += sizeof(unsigned int);
			*(unsigned short*)pos = htons(4);
			pos += sizeof(unsigned short);
			memcpy(pos, &dcache->addr, 4);
			pos += 4;
			sendto(engine->service, rbuffer, pos - rbuffer, 0, (struct sockaddr*)source, sizeof(struct sockaddr_in));
			return;
		}
	}

	if(rhdr->rcode == 0) {
		cache = proxy_cache_insert(ntohs(hdr->id), source);
		if(cache == NULL)
			rhdr->rcode = 2;
		else {
			hdr->id = htons(cache->new_id);
			if(sendto(engine->dns_udp, buffer, size, 0, (struct sockaddr*)&engine->dns_addr, sizeof(struct sockaddr_in)) != size)
				rhdr->rcode = 2;
		}
	}
	if(rhdr->rcode != 0) {
		sendto(engine->service, rbuffer, sizeof(DNS_HDR), 0, (struct sockaddr*)source, sizeof(struct sockaddr_in));
		return;
	}
}

void process_response(PROXY_ENGINE *engine, char* buffer, int size, struct sockaddr_in *source)
{
	DNS_HDR *hdr;
	PROXY_CACHE * cache;

	hdr = (DNS_HDR*)buffer;
	if(hdr->qr != 1 || hdr->tc != 0 || ntohs(hdr->q_count) <1 || ntohs(hdr->ans_count) < 1)
		return;

	cache = proxy_cache_search(ntohs(hdr->id));
	if(cache) {
		hdr->id = htons(cache->old_id);
		sendto(engine->service, buffer, size, 0, (struct sockaddr*)&cache->address, sizeof(struct sockaddr_in));
		proxy_cache_delete(cache);
	}
}

int dnsproxy(unsigned short local_port, const char* remote_addr, unsigned short remote_port)
{
#ifndef _WIN32
	static const int one = 1;
#endif
	struct timeval timeout;
	struct sockaddr_in addr;
	fd_set readfds;
	int nfds, fds, addrlen, buflen;
	PROXY_ENGINE *engine, _engine;
	static char buffer[PACKAGE_SIZE];

	engine = &_engine;
	memset(&_engine, 0, sizeof(PROXY_ENGINE));

	engine->dns_addr.sin_family = AF_INET;
	engine->dns_addr.sin_addr.s_addr = inet_addr(remote_addr);
	engine->dns_addr.sin_port = htons(remote_port);

	engine->service = socket(AF_INET, SOCK_DGRAM, 0);
	if(engine->service == INVALID_SOCKET) {
		perror("create socket");
		return -1;
	}
#ifndef _WIN32
	setsockopt(engine->service, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(local_port);
	if(bind(engine->service, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		perror("bind service port");
		return -1;
	}

	engine->dns_udp = socket(AF_INET, SOCK_DGRAM, 0);
	if(engine->dns_udp == INVALID_SOCKET) {
		perror("create socket");
		return -1;
	}

	while(1) {
		FD_ZERO(&readfds);
		FD_SET(engine->service, &readfds);
		FD_SET(engine->dns_udp, &readfds);
		nfds = 0;
		if(engine->service > engine->dns_udp)
			nfds = (int)engine->service + 1;
		else
			nfds = (int)engine->dns_udp + 1;
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		fds = select(nfds, &readfds, NULL, NULL, &timeout);
		if(fds == 0)
			proxy_cache_clean();
		else if(fds > 0) {
			if(FD_ISSET(engine->service, &readfds)) {
				addrlen = sizeof(struct sockaddr_in);
				buflen = recvfrom(engine->service, buffer, PACKAGE_SIZE, 0, (struct sockaddr*)&addr, &addrlen);
				if(buflen > sizeof(DNS_HDR))
					process_query(engine, buffer, buflen, &addr);
			}
			if(FD_ISSET(engine->dns_udp, &readfds)) {
				addrlen = sizeof(struct sockaddr_in);
				buflen = recvfrom(engine->dns_udp, buffer, PACKAGE_SIZE, 0, (struct sockaddr*)&addr, &addrlen);
				if(buflen >= sizeof(DNS_HDR))
					process_response(engine, buffer, buflen, &addr);
			}
		}
	}
	return 0;
}

struct xoption options[] = {
	{'v', "version", xargument_no, NULL, 'v'},
	{'h', "help", xargument_no, NULL, 'h'},
	{'p', "port", xargument_required, NULL, 'p'},
	{'P', "remote-port", xargument_required, NULL, 'P'},
	{'R', "remote-addr", xargument_required, NULL, 'R'},
	{'f', "hosts-file", xargument_required, NULL, 'f'},
	{0, NULL, xargument_no, NULL, 0},
};

static void display_help()
{
	printf("Usage: dnsproxy [options]\n"
		"  -p <port> or --port=<port>\n"
		"                       (local bind port)\n"
		"  -R <ip> or --remote-addr=<ip>\n"
		"                       (remote server ip address)\n"
		"  -P <port> or --remote-port=<port>\n"
		"                       (remote server port)\n"
		"  -f <file> or --hosts-file=<file>\n"
		"                       (user-defined hosts file)\n"
		"  -h, --help           (print help and exit)\n"
		"  -v, --version        (print version and exit)\n");
};

int main(int argc, const char* argv[])
{
#ifdef _WIN32
	WSADATA wsaData;
#endif
	int opt, optind;
	const char *optarg;
	const char *hosts_file = NULL;
	const char *remote_addr = "8.8.8.8";
	unsigned short local_port = 53, remote_port = 53;

	optind = 0;
	opt = xgetopt(argc, argv, options, &optind, &optarg);
	while(opt != -1) {
		switch(opt) {
		case 'p':
			local_port = (unsigned short)atoi(optarg);
			break;
		case 'P':
			remote_port = (unsigned short)atoi(optarg);
			break;
		case 'R':
			remote_addr = optarg;
			break;
		case 'f':
			hosts_file = optarg;
			break;
		case 'v':
			printf("version: %s\n", VERSION);
			return 0;
		case 'h':
		default:
			display_help();
			return -1;
		}
		opt = xgetopt(argc, argv, options, &optind, &optarg);
	}

	srand((unsigned int)time(NULL));
#ifdef _WIN32
	WSAStartup(MAKEWORD(2,2), &wsaData);
#endif

	proxy_cache_init(5);
	domain_cache_init(hosts_file);
	return dnsproxy(local_port, remote_addr, remote_port);
}
