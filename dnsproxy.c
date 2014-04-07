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

#if defined(_MSC_VER)
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"mswsock")
#endif

typedef struct {
	SOCKET service;
	int use_tcp;
	SOCKET dns_udp;
	SOCKET dns_tcp;
	struct sockaddr_in dns_addr;
	unsigned int head, rear;
	char buffer[PACKAGE_SIZE * 3];
} PROXY_ENGINE;

static void process_query(PROXY_ENGINE *engine)
{
	DNS_QES *qes, *rqes;
	DNS_HDR *hdr, *rhdr;
	TRANSPORT_CACHE *cache;
	DOMAIN_CACHE *dcache;
	socklen_t addrlen;
	struct sockaddr_in source;
	char *pos, *head, *rear;
	char domain[PACKAGE_SIZE];
	char rbuffer[PACKAGE_SIZE];
	char qbuffer[PACKAGE_SIZE + sizeof(unsigned short)], *buffer = qbuffer + sizeof(unsigned short);
	int size, len, dlen, q_count, q_len;

	addrlen = sizeof(struct sockaddr_in);
	size = recvfrom(engine->service, buffer, PACKAGE_SIZE, 0, (struct sockaddr*)&source, &addrlen);
	if(size <= sizeof(DNS_HDR))
		return;

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
		dlen = 0;
		memset(domain, 0, PACKAGE_SIZE);
		pos = head;
		while(pos < rear) {
			len = (int)*pos++;
			if(len < 0 || len > 63 || (pos + len) > (rear - sizeof(DNS_QES))) {
				rhdr->rcode = 1;
				break;
			}
			if(len > 0) {
				if(dlen > 0)
					domain[dlen++] = '.';
				while(len-- > 0)
					domain[dlen++] = (char)tolower(*pos++);
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
			*(unsigned int*)pos = dcache->addr.s_addr;
			pos += sizeof(unsigned int);
			sendto(engine->service, rbuffer, pos - rbuffer, 0, (struct sockaddr*)&source, sizeof(struct sockaddr_in));
			return;
		}
	}

	if(rhdr->rcode == 0) {
		cache = transport_cache_insert(ntohs(hdr->id), &source);
		if(cache == NULL)
			rhdr->rcode = 2;
		else {
			hdr->id = htons(cache->new_id);
			if(!engine->use_tcp) {
				if(sendto(engine->dns_udp, buffer, size, 0, (struct sockaddr*)&engine->dns_addr, sizeof(struct sockaddr_in)) != size)
					rhdr->rcode = 2;
			}
			else {
				if(engine->dns_tcp == INVALID_SOCKET) {
					engine->head = 0;
					engine->rear = 0;
					engine->dns_tcp = socket(AF_INET, SOCK_STREAM, 0);
					if(engine->dns_tcp != INVALID_SOCKET) {
						if(connect(engine->dns_tcp, (struct sockaddr*)&engine->dns_addr, sizeof(struct sockaddr_in)) != 0) {
							closesocket(engine->dns_tcp);
							engine->dns_tcp = INVALID_SOCKET;
						}
					}
				}
				if(engine->dns_tcp == INVALID_SOCKET)
					rhdr->rcode = 2;
				else{
					len = size + sizeof(unsigned short);
					*(unsigned short*)qbuffer = htons((unsigned short)size);
					if(send(engine->dns_tcp, qbuffer, len, 0) != len) {
						closesocket(engine->dns_tcp);
						engine->dns_tcp = INVALID_SOCKET;
						rhdr->rcode = 2;
					}
				}
			}
		}
	}
	if(rhdr->rcode != 0) {
		sendto(engine->service, rbuffer, sizeof(DNS_HDR), 0, (struct sockaddr*)&source, sizeof(struct sockaddr_in));
		return;
	}
}

static void process_response(PROXY_ENGINE *engine, char* buffer, int size)
{
	DNS_HDR *hdr;
	TRANSPORT_CACHE *cache;

	hdr = (DNS_HDR*)buffer;
	if(hdr->qr != 1 || hdr->tc != 0 || ntohs(hdr->q_count) <1 || ntohs(hdr->ans_count) < 1)
		return;

	cache = transport_cache_search(ntohs(hdr->id));
	if(cache) {
		hdr->id = htons(cache->old_id);
		sendto(engine->service, buffer, size, 0, (struct sockaddr*)&cache->address, sizeof(struct sockaddr_in));
		transport_cache_delete(cache);
	}
}

static void process_response_udp(PROXY_ENGINE *engine)
{
	int size;
	socklen_t addrlen;
	struct sockaddr_in source;
	char buffer[PACKAGE_SIZE];

	addrlen = sizeof(struct sockaddr_in);
	size = recvfrom(engine->dns_udp, buffer, PACKAGE_SIZE, 0, (struct sockaddr*)&source, &addrlen);
	if(size < sizeof(DNS_HDR))
		return;

	process_response(engine, buffer, size);
}

static void process_response_tcp(PROXY_ENGINE *engine)
{
	int to_down, size;
	unsigned int len, buflen;

	to_down = 0;
	size = recv(engine->dns_tcp, engine->buffer + engine->rear, PACKAGE_SIZE + sizeof(unsigned short), 0);
	if(size < 1)
		to_down = 1;
	else {
		engine->rear += size;
		while((buflen = engine->rear - engine->head) > sizeof(unsigned short)) {
			len = ntohs(*(unsigned short*)(engine->buffer + engine->head));
			if(len > PACKAGE_SIZE) {
				to_down = 1;
				break;
			}
			if(len + sizeof(unsigned short) > buflen)
				break;
			process_response(engine, engine->buffer + engine->head + sizeof(unsigned short), len);
			engine->head += len + sizeof(unsigned short);
			if(engine->head == engine->rear) {
				engine->head = 0;
				engine->rear = 0;
			}
			else if(engine->head > PACKAGE_SIZE) {
				len = engine->rear - engine->head;
				memmove(engine->buffer, engine->buffer + engine->head, len);
				engine->head = 0;
				engine->rear = len;
			}
		}
	}

	if(to_down){
		closesocket(engine->dns_tcp);
		engine->dns_tcp = INVALID_SOCKET;
		return;
	}
}

static int dnsproxy(unsigned short local_port, const char* remote_addr, unsigned short remote_port, int remote_tcp)
{
#ifndef _WIN32
	static const int one = 1;
#endif
	int maxfd, fds;
	fd_set readfds;
	struct timeval timeout;
	struct sockaddr_in addr;
	PROXY_ENGINE *engine, _engine;

	engine = &_engine;
	memset(&_engine, 0, sizeof(PROXY_ENGINE));

	engine->use_tcp = remote_tcp;
	engine->dns_udp = INVALID_SOCKET;
	engine->dns_tcp = INVALID_SOCKET;

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

	if(!engine->use_tcp) {
		engine->dns_udp = socket(AF_INET, SOCK_DGRAM, 0);
		if(engine->dns_udp == INVALID_SOCKET) {
			perror("create socket");
			return -1;
		}
	}

	while(1) {
		FD_ZERO(&readfds);
		FD_SET(engine->service, &readfds);
		maxfd = (int)engine->service;
		if(!engine->use_tcp) {
			FD_SET(engine->dns_udp, &readfds);
			if(maxfd < (int)engine->dns_udp)
				maxfd = (int)engine->dns_udp;
		}
		else if(engine->dns_tcp != INVALID_SOCKET) {
			FD_SET(engine->dns_tcp, &readfds);
			if(maxfd < (int)engine->dns_tcp)
				maxfd = (int)engine->dns_tcp;
		}
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		fds = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
		if(fds == 0)
			transport_cache_clean();
		else if(fds > 0) {
			if(!engine->use_tcp) {
				if(FD_ISSET(engine->dns_udp, &readfds))
					process_response_udp(engine);
			}
			else {
				if(engine->dns_tcp != INVALID_SOCKET
					&& FD_ISSET(engine->dns_tcp, &readfds))
					process_response_tcp(engine);
			}
			if(FD_ISSET(engine->service, &readfds))
				process_query(engine);
		}
	}
	return 0;
}

struct xoption options[] = {
	{'v', "version", xargument_no, NULL, 'v'},
	{'h', "help", xargument_no, NULL, 'h'},
	{'d', "daemon", xargument_no, NULL, 'd'},
	{'p', "port", xargument_required, NULL, 'p'},
	{'T', "remote-tcp", xargument_no, NULL, 'T'},
	{'P', "remote-port", xargument_required, NULL, 'P'},
	{'R', "remote-addr", xargument_required, NULL, 'R'},
	{'f', "hosts-file", xargument_required, NULL, 'f'},
	{0, NULL, xargument_no, NULL, 0},
};

static void display_help()
{
	printf("Usage: dnsproxy [options]\n"
		"  -d or --daemon\n"
		"                       (daemon mode)\n"
		"  -p <port> or --port=<port>\n"
		"                       (local bind port, default 53)\n"
		"  -R <ip> or --remote-addr=<ip>\n"
		"                       (remote server ip, default 8.8.8.8)\n"
		"  -P <port> or --remote-port=<port>\n"
		"                       (remote server port, default 53)\n"
		"  -T or --remote-tcp\n"
		"                       (connect remote server in tcp, default no)\n"
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
	int use_daemon = 0;
	int remote_tcp = 0;
	int transport_timeout = 5;
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
		case 'T':
			remote_tcp = 1;
			break;
		case 'f':
			hosts_file = optarg;
			break;
		case 'd':
			use_daemon = 1;
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

#ifdef _WIN32
	WSAStartup(MAKEWORD(2,2), &wsaData);
	if(use_daemon) {
		freopen("NUL", "r", stdin);
		freopen("NUL", "w", stdout);
		freopen("NUL", "w", stderr);
		FreeConsole();
	}
#else
	if(use_daemon) {
		int fd;
		pid_t pid = fork();
		if(pid < 0) {
			perror("fork");
			return -1;
		}
		if(pid != 0)
			exit(0);
		pid = setsid();
		if(pid < -1) {
			perror("setsid");
			return -1;
		}
		chdir("/");
		fd = open ("/dev/null", O_RDWR, 0);
		if(fd != -1) {
			dup2 (fd, 0);
			dup2 (fd, 1);
			dup2 (fd, 2);
			if(fd > 2)
				close (fd);
		}
		umask(0);
	}
	signal(SIGPIPE, SIG_IGN);
#endif

	printf("Startup\n"
		"  local bind : %d\n"
		"  remote addr: %s\n"
		"  remote port: %d\n"
		"  remote tcp : %s\n"
		, local_port
		, remote_addr
		, remote_port
		, remote_tcp? "on": "off");

	srand((unsigned int)time(NULL));
	domain_cache_init(hosts_file);
	transport_cache_init(transport_timeout);
	return dnsproxy(local_port, remote_addr, remote_port, remote_tcp);
}
