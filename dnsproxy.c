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
#include "asciilogo.h"

#ifndef VERSION
#define VERSION "development"
#endif

#define PACKAGE_SIZE 512

#if defined(_MSC_VER)
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"mswsock")
#endif

typedef struct {
	int tcp;
	SOCKET sock;
	struct sockaddr_in addr;
	unsigned int head, rear;
	char buffer[PACKAGE_SIZE * 3];
} REMOTE_DNS;

typedef struct {
	SOCKET server;
	REMOTE_DNS primary;
} PROXY_ENGINE;

static const int enable = 1;

static void process_query(PROXY_ENGINE *engine)
{
	REMOTE_DNS *dns;
	DNS_QES *qes, *rqes;
	DNS_HDR *hdr, *rhdr;
	DOMAIN_CACHE *dcache;
	TRANSPORT_CACHE *tcache;
	socklen_t addrlen;
	struct sockaddr_in source;
	char *pos, *head, *rear;
	char domain[PACKAGE_SIZE];
	char rbuffer[PACKAGE_SIZE];
	char qbuffer[PACKAGE_SIZE + sizeof(unsigned short)], *buffer = qbuffer + sizeof(unsigned short);
	int size, len, dlen, q_count, q_len;

	addrlen = sizeof(struct sockaddr_in);
	size = recvfrom(engine->server, buffer, PACKAGE_SIZE, 0, (struct sockaddr*)&source, &addrlen);
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
	head = buffer + sizeof(DNS_HDR);
	rear = buffer + size;
	if(hdr->qr != 0 || hdr->tc != 0 || q_count < 1)
		rhdr->rcode = 1;
	else {
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
			sendto(engine->server, rbuffer, pos - rbuffer, 0, (struct sockaddr*)&source, sizeof(struct sockaddr_in));
			return;
		}
	}

	if(rhdr->rcode == 0) {
		tcache = transport_cache_insert(ntohs(hdr->id), &source);
		if(tcache == NULL)
			rhdr->rcode = 2;
		else {
			dns = &engine->primary;
			hdr->id = htons(tcache->new_id);
			if(!dns->tcp) {
				if(sendto(dns->sock, buffer, size, 0, (struct sockaddr*)&dns->addr, sizeof(struct sockaddr_in)) != size)
					rhdr->rcode = 2;
			}
			else {
				if(dns->sock == INVALID_SOCKET) {
					dns->head = 0;
					dns->rear = 0;
					dns->sock = socket(AF_INET, SOCK_STREAM, 0);
					if(dns->sock != INVALID_SOCKET) {
						setsockopt(dns->sock, IPPROTO_TCP, TCP_NODELAY, (void*)&enable, sizeof(enable));
						if(connect(dns->sock, (struct sockaddr*)&dns->addr, sizeof(struct sockaddr_in)) != 0) {
							closesocket(dns->sock);
							dns->sock = INVALID_SOCKET;
						}
					}
				}
				if(dns->sock == INVALID_SOCKET)
					rhdr->rcode = 2;
				else{
					pos = qbuffer;
					len = size + sizeof(unsigned short);
					*(unsigned short*)pos = htons((unsigned short)size);
					if(send(dns->sock, qbuffer, len, 0) != len) {
						closesocket(dns->sock);
						dns->sock = INVALID_SOCKET;
						rhdr->rcode = 2;
					}
				}
			}
			if(rhdr->rcode != 0)
				transport_cache_delete(tcache);
		}
	}
	if(rhdr->rcode != 0) {
		sendto(engine->server, rbuffer, sizeof(DNS_HDR), 0, (struct sockaddr*)&source, sizeof(struct sockaddr_in));
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
		sendto(engine->server, buffer, size, 0, (struct sockaddr*)&cache->address, sizeof(struct sockaddr_in));
		transport_cache_delete(cache);
	}
}

static void process_response_udp(PROXY_ENGINE *engine)
{
	int size;
	socklen_t addrlen;
	struct sockaddr_in source;
	REMOTE_DNS *dns = &engine->primary;

	addrlen = sizeof(struct sockaddr_in);
	size = recvfrom(dns->sock, dns->buffer, PACKAGE_SIZE, 0, (struct sockaddr*)&source, &addrlen);
	if(size < sizeof(DNS_HDR))
		return;

	process_response(engine, dns->buffer, size);
}

static void process_response_tcp(PROXY_ENGINE *engine)
{
	char *pos;
	int to_down, size;
	unsigned int len, buflen;
	REMOTE_DNS *dns = &engine->primary;

	to_down = 0;
	size = recv(dns->sock, dns->buffer + dns->rear, PACKAGE_SIZE + sizeof(unsigned short), 0);
	if(size < 1)
		to_down = 1;
	else {
		dns->rear += size;
		while((buflen = dns->rear - dns->head) > sizeof(unsigned short)) {
			pos = dns->buffer + dns->head;
			len = ntohs(*(unsigned short*)pos);
			if(len > PACKAGE_SIZE) {
				to_down = 1;
				break;
			}
			if(len + sizeof(unsigned short) > buflen)
				break;
			process_response(engine, pos + sizeof(unsigned short), len);
			dns->head += len + sizeof(unsigned short);
			if(dns->head == dns->rear) {
				dns->head = 0;
				dns->rear = 0;
			}
			else if(dns->head > PACKAGE_SIZE) {
				len = dns->rear - dns->head;
				memmove(dns->buffer, dns->buffer + dns->head, len);
				dns->head = 0;
				dns->rear = len;
			}
		}
	}

	if(to_down){
		closesocket(dns->sock);
		dns->sock = INVALID_SOCKET;
	}
}

static int dnsproxy(unsigned short local_port, const char* remote_addr, unsigned short remote_port, int remote_tcp)
{
	int maxfd, fds;
	fd_set readfds;
	struct timeval timeout;
	struct sockaddr_in addr;
	PROXY_ENGINE _engine, *engine = &_engine;
	REMOTE_DNS *dns = &_engine.primary;

	engine = &_engine;
	memset(&_engine, 0, sizeof(PROXY_ENGINE));

	dns->tcp = remote_tcp;
	dns->sock = INVALID_SOCKET;
	dns->addr.sin_family = AF_INET;
	dns->addr.sin_addr.s_addr = inet_addr(remote_addr);
	dns->addr.sin_port = htons(remote_port);

	engine->server = socket(AF_INET, SOCK_DGRAM, 0);
	if(engine->server == INVALID_SOCKET) {
		perror("create socket");
		return -1;
	}
	setsockopt(engine->server, SOL_SOCKET, SO_REUSEADDR, (void*)&enable, sizeof(enable));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(local_port);
	if(bind(engine->server, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		perror("bind service port");
		return -1;
	}

	if(!dns->tcp) {
		dns->sock = socket(AF_INET, SOCK_DGRAM, 0);
		if(dns->sock == INVALID_SOCKET) {
			perror("create socket");
			return -1;
		}
	}

	while(1) {
		FD_ZERO(&readfds);
		FD_SET(engine->server, &readfds);
		maxfd = (int)engine->server;
		if(dns->sock != INVALID_SOCKET) {
			FD_SET(dns->sock, &readfds);
			if(maxfd < (int)dns->sock)
				maxfd = (int)dns->sock;
		}
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		fds = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
		if(fds == 0)
			transport_cache_clean();
		else if(fds > 0) {
			if(dns->sock != INVALID_SOCKET
				&& FD_ISSET(dns->sock, &readfds)) {
				if(dns->tcp)
					process_response_tcp(engine);
				else
					process_response_udp(engine);
			}
			if(FD_ISSET(engine->server, &readfds))
				process_query(engine);
		}
	}
	return 0;
}

struct xoption options[] = {
	{'v', "version", xargument_no, NULL, -1},
	{'h', "help", xargument_no, NULL, -1},
	{'d', "daemon", xargument_no, NULL, -1},
	{'p', "port", xargument_required, NULL, -1},
	{'T', "remote-tcp", xargument_no, NULL, -1},
	{'P', "remote-port", xargument_required, NULL, -1},
	{'R', "remote-addr", xargument_required, NULL, -1},
	{'f', "hosts-file", xargument_required, NULL, -1},
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
			printf("%s"
				" * version: %s\n",
				ascii_logo,
				VERSION);
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

	printf("%s"
		" * runing at %d\n"
		" * transport to %s:%d,%s\n"
		, ascii_logo
		, local_port
		, remote_addr
		, remote_port
		, remote_tcp? "tcp": "udp");

	srand((unsigned int)time(NULL));
	domain_cache_init(hosts_file);
	transport_cache_init(transport_timeout);
	return dnsproxy(local_port, remote_addr, remote_port, remote_tcp);
}
