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

typedef struct {
	int tcp;
	SOCKET sock;
	struct sockaddr_in addr;
	unsigned int head;
	unsigned int rear;
	unsigned int capacity;
	char buffer[0];
} BUFSOCKET;
