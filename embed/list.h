/*
 * Copyright 2014, Vietor Liu <vietor.liu at gmail.com>
 * All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef LIST_H
#define LIST_H

#include "embed.h"

struct list {
	struct list *prev;
	struct list *next;
};

static inline void list_init(struct list *list)
{
	list->prev = list;
	list->next = list;
}

static inline void list_insert(struct list *list, struct list *elm)
{
	elm->prev = list;
	elm->next = list->next;
	list->next = elm;
	elm->next->prev = elm;
}

static inline void list_remove(struct list *elm)
{
	elm->prev->next = elm->next;
	elm->next->prev = elm->prev;
	list_init(elm);
}

static inline int list_empty(const struct list *list)
{
	return list->next == list;
}

static inline void list_insert_list(struct list *list, struct list *other)
{
	if (list_empty(other))
		return;

	other->next->prev = list;
	other->prev->next = list->next;
	list->next->prev = other->prev;
	list->next = other->next;
	list_init(other);
}

#define list_for_each(pos, head, member)				\
	for (pos = 0, pos = container_of((head)->next, pos, member);	\
		&pos->member != (head);					\
		pos = container_of(pos->member.next, pos, member))

#define list_for_each_safe(pos, tmp, head, member)			\
	for (pos = 0, tmp = 0, 						\
		pos = container_of((head)->next, pos, member),		\
		tmp = container_of((pos)->member.next, tmp, member);	\
		&pos->member != (head);					\
		pos = tmp,							\
		tmp = container_of(pos->member.next, tmp, member))

#define list_for_each_reverse(pos, head, member)			\
	for (pos = 0, pos = container_of((head)->prev, pos, member);	\
		&pos->member != (head);					\
		pos = container_of(pos->member.prev, pos, member))

#define list_for_each_reverse_safe(pos, tmp, head, member)		\
	for (pos = 0, tmp = 0, 						\
		pos = container_of((head)->prev, pos, member),	\
		tmp = container_of((pos)->member.prev, tmp, member);	\
		&pos->member != (head);					\
		pos = tmp,							\
		tmp = container_of(pos->member.prev, tmp, member))

#endif
