#include "dnsproxy.h"

static struct {
	unsigned int count;
	struct rbtree rb_name;
} domain_cache;

static int name_search(const void* k, const struct rbnode* r)
{
	DOMAIN_CACHE *right;
	right = rbtree_entry(r, DOMAIN_CACHE, rb_name);
	return strcmp((const char*) k, right->domain);
}

static int name_compare(const struct rbnode* l, const struct rbnode* r)
{
	DOMAIN_CACHE *left, *right;
	left = rbtree_entry(l, DOMAIN_CACHE, rb_name);
	right = rbtree_entry(r, DOMAIN_CACHE, rb_name);
	return strcmp(left->domain, right->domain);
}

void domain_cache_init()
{
	rbtree_init(&domain_cache.rb_name, name_search, name_compare);
}

DOMAIN_CACHE* domain_cache_search(char* domain)
{
	struct rbnode *node;
	node = rbtree_search(&domain_cache.rb_name, domain);
	if(node == NULL)
		return NULL;
	return rbtree_entry(node, DOMAIN_CACHE, rb_name);
}
