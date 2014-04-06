#include "dnsproxy.h"

typedef struct {
	SOCKET local;
	SOCKET remote;
	struct sockaddr_in remote_addr;
	fd_set readfds;
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
			sendto(engine->local, rbuffer, pos - rbuffer, 0, (struct sockaddr*)source, sizeof(struct sockaddr_in));
			return;
		}
	}

	if(rhdr->rcode == 0) {
		cache = proxy_cache_insert(ntohs(hdr->id), source);
		if(cache == NULL)
			rhdr->rcode = 2;
		else {
			hdr->id = htons(cache->new_id);
			if(sendto(engine->remote, buffer, size, 0, (struct sockaddr*)&engine->remote_addr, sizeof(struct sockaddr_in)) != size)
				rhdr->rcode = 2;
		}
	}
	if(rhdr->rcode != 0) {
		sendto(engine->local, rbuffer, sizeof(DNS_HDR), 0, (struct sockaddr*)source, sizeof(struct sockaddr_in));
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
		sendto(engine->local, buffer, size, 0, (struct sockaddr*)&cache->address, sizeof(struct sockaddr_in));
		proxy_cache_delete(cache);
	}
}

int dnsproxy(unsigned short local_port, const char* remote_addr, unsigned short remote_port)
{
	struct timeval timeout;
	struct sockaddr_in addr;
	char buffer[PACKAGE_SIZE];
	int nfds, fds, addrlen, buflen;
	PROXY_ENGINE *engine, _engine;

	engine = &_engine;
	memset(&_engine, 0, sizeof(PROXY_ENGINE));

	engine->remote_addr.sin_family = AF_INET;
	engine->remote_addr.sin_addr.s_addr = inet_addr(remote_addr);
	engine->remote_addr.sin_port = htons(remote_port);

	engine->local = socket(AF_INET, SOCK_DGRAM, 0);
	if(engine->local == INVALID_SOCKET) {
		perror("create socket");
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(local_port);
	if(bind(engine->local, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		perror("bind service port");
		return -1;
	}

	engine->remote = socket(AF_INET, SOCK_DGRAM, 0);
	if(engine->remote == INVALID_SOCKET) {
		perror("create socket");
		return -1;
	}

	while(1) {
		FD_ZERO(&engine->readfds);
		FD_SET(engine->local, &engine->readfds);
		FD_SET(engine->remote, &engine->readfds);	
		nfds = 0;
		if(engine->local > engine->remote)
			nfds = (int)engine->local + 1;
		else
			nfds = (int)engine->remote + 1;
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		fds = select(nfds, &engine->readfds, NULL, NULL, &timeout);
		if(fds == 0)
			proxy_cache_clean();
		else if(fds > 0) {
			if(FD_ISSET(engine->local, &engine->readfds)) {
				addrlen = sizeof(struct sockaddr_in);
				buflen = recvfrom(engine->local, buffer, PACKAGE_SIZE, 0, (struct sockaddr*)&addr, &addrlen);
				if(buflen > sizeof(DNS_HDR))
					process_query(engine, buffer, buflen, &addr);
			}
			if(FD_ISSET(engine->remote, &engine->readfds)) {
				addrlen = sizeof(struct sockaddr_in);
				buflen = recvfrom(engine->remote, buffer, PACKAGE_SIZE, 0, (struct sockaddr*)&addr, &addrlen);
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

int main(int argc, char* argv[])
{
	WSADATA wsaData;
	int opt, optind;
	char *optarg;
	const char* hosts_file = NULL;
	const char* remote_addr = "8.8.8.8";
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
	WSAStartup(MAKEWORD(2,2), &wsaData);

	proxy_cache_init();
	domain_cache_init(hosts_file);
	return dnsproxy(local_port, remote_addr, remote_port);
}
