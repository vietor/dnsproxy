#include "dnsproxy.h"

static struct {
	unsigned int count;
	unsigned short seq;
	struct rbtree rb_new;
	struct rbtree rb_expire;
} g_cache;

static int new_search(const void* k, const struct rbnode* r)
{
	PROXY_CACHE *right;
	right = rbtree_entry(r, PROXY_CACHE, rb_new);
	return (unsigned short)k - right->new_id;
}

static int new_compare(const struct rbnode* l, const struct rbnode* r)
{
	PROXY_CACHE *left, *right;
	left = rbtree_entry(l, PROXY_CACHE, rb_new);
	right = rbtree_entry(r, PROXY_CACHE, rb_new);
	return left->new_id - right->new_id;
}

static int expire_compare(const struct rbnode* l, const struct rbnode* r)
{
	PROXY_CACHE *left, *right;
	left = rbtree_entry(l, PROXY_CACHE, rb_expire);
	right = rbtree_entry(r, PROXY_CACHE, rb_expire);
	return (int)(left->expire - right->expire);
}

void proxy_cache_init()
{
	g_cache.count = 0;
	g_cache.seq = (unsigned short)rand();
	rbtree_init(&g_cache.rb_new, new_search, new_compare);
	rbtree_init(&g_cache.rb_expire, NULL, expire_compare);
}

PROXY_CACHE* proxy_cache_add(unsigned short old_id, struct sockaddr_in *address)
{
	PROXY_CACHE *cache = (PROXY_CACHE*)calloc(1, sizeof(PROXY_CACHE));
	if(cache == NULL)
		return NULL;
	cache->new_id = ++g_cache.seq;
	cache->expire = time(NULL);
	cache->old_id = old_id;
	memcpy(&cache->address, address, sizeof(struct sockaddr_in));
	++g_cache.count;
	rbtree_insert(&g_cache.rb_new, &cache->rb_new);
	rbtree_insert(&g_cache.rb_expire, &cache->rb_expire);
	return cache;
}

PROXY_CACHE* proxy_cache_search(unsigned short new_id)
{
	struct rbnode *node;
	node = rbtree_search(&g_cache.rb_new, (void*)new_id);
	if(node == NULL)
		return NULL;
	return rbtree_entry(node, PROXY_CACHE, rb_new);
}

void proxy_cache_del(PROXY_CACHE *cache)
{
	--g_cache.count;
	rbtree_delete(&g_cache.rb_new, &cache->rb_new);
	rbtree_delete(&g_cache.rb_expire, &cache->rb_expire);
	free(cache);
}
