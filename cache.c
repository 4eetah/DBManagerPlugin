#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "structures.h"
#include "db.h"

#define DBG_CACHE 0
#if DBG_CACHE
#define dbg_cache(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbg_cache(...)
#endif

/* Robert Jenkins' 32 bit integer hash function */
static uint32_t hash32(uint32_t a)
{
    a = (a+0x7ed55d16) + (a<<12);
    a = (a^0xc761c23c) ^ (a>>19);
    a = (a+0x165667b1) + (a<<5);
    a = (a+0xd3a2646c) ^ (a<<9);
    a = (a+0xfd7046c5) + (a<<3);
    a = (a^0xb55a4f09) ^ (a>>16);
    return a;
}

/* djb2 */
static unsigned long hashStr(unsigned char *str)
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c;

    return hash;
}

static int cache_resizeip(struct cache_ip *c, size_t newsize)
{
    dbg_cache("%s: from %lu to %lu\n", __func__, c->size, newsize);
    struct cache_ip temp;
    if (!cache_initip(&temp, newsize))
        return 0;

    int i;
    for (i = 0; i < c->size; i++) {
        if (c->map[i].ipkey) {
            cache_putip(&temp, c->map[i].ipkey, c->map[i].user, c->map[i].passwd);
            pl->myfree(c->map[i].user);
            pl->myfree(c->map[i].passwd);
        }
    }
    pl->myfree(c->map);
    c->elements = temp.elements;
    c->size = temp.size;
    c->map = temp.map;

    return 1;
}

void cache_putip(struct cache_ip *c, uint32_t key, unsigned char *user, unsigned char *passwd)
{
    pthread_mutex_lock(&c->mux);
    if (c->elements >= c->size/2) {
        if (!cache_resizeip(c, c->size*2)) {
            pthread_mutex_unlock(&c->mux);
            return;
        }
    }

    size_t id;
    for (id = hash32(key) % c->size; c->map[id].ipkey != 0; id = (id+1) % c->size)
        if (c->map[id].ipkey == key)
            break;

    if (c->map[id].ipkey != 0) {
        pl->myfree(c->map[id].user);
        pl->myfree(c->map[id].passwd);
    } else {
        c->elements++;
    }
    c->map[id].ipkey = key;
    c->map[id].user = pl->mystrdup(user);
    c->map[id].passwd = pl->mystrdup(passwd);

    dbg_cache("%s: size:%lu, elemnts:%lu, id:%lu, key:%u, val:{%s,%s}\n", __func__, c->size, c->elements, id, key, user, passwd);
    pthread_mutex_unlock(&c->mux);
}

int cache_getip(struct cache_ip *c, uint32_t key, unsigned char **user, unsigned char **passwd)
{
    pthread_mutex_lock(&c->mux);
#if DBG_CACHE
    cache_printip(c);
#endif
    size_t id;
    for (id = hash32(key) % c->size; c->map[id].ipkey != 0; id = (id+1) % c->size)
        if (c->map[id].ipkey == key) {
            *user = pl->mystrdup(c->map[id].user);
            *passwd = pl->mystrdup(c->map[id].passwd);
            dbg_cache("%s lookup success: size:%lu, elemnts:%lu, id:%lu, key:%u, val:{%s,%s}\n", __func__,
                    c->size, c->elements, id, key, c->map[id].user, c->map[id].passwd);
            pthread_mutex_unlock(&c->mux);
            return 1;
        }
    dbg_cache("%s lookup fail: size:%lu, elemnts:%lu, id:%lu, key:%u, val:{%s,%s}\n", __func__,
            c->size, c->elements, id, key, c->map[id].user, c->map[id].passwd);

    pthread_mutex_unlock(&c->mux);
    return 0;
}

static int cache_resizeapp(struct cache_ap *c, size_t newsize)
{
    dbg_cache("%s: from %lu to %lu\n", __func__, c->size, newsize);
    struct cache_ap temp;
    if (!cache_initapp(&temp, newsize))
        return 0;

    int i;
    for (i = 0; i < c->size; i++) {
        if (c->map[i].appkey) {
            cache_putapp_hash(&temp, c->map[i].appkey, c->map[i].passwd);
            pl->myfree(c->map[i].passwd);
        }
    }
    pl->myfree(c->map);
    c->elements = temp.elements;
    c->size = temp.size;
    c->map = temp.map;

    return 1;
}

static void cache_putapp_hash(struct cache_ap *c, unsigned long hash, unsigned char *passwd)
{
    size_t id;
    for (id = hash % c->size; c->map[id].appkey != 0; id = (id+1) % c->size)
        if (c->map[id].appkey == hash)
            break;
    
    if (c->map[id].appkey != 0) {
        pl->myfree(c->map[id].passwd);
    } else {
        c->elements++;
    }
    c->map[id].appkey = hash;
    c->map[id].passwd = pl->mystrdup(passwd);

    dbg_cache("%s: size:%lu, elemnts:%lu, id:%lu, key:{%lu}, val:%s\n", __func__, c->size, c->elements, id, hash, passwd);

}
void cache_putapp(struct cache_ap *c, unsigned char *app, unsigned char *passwd)
{
    pthread_mutex_lock(&c->mux);
    if (c->elements >= c->size/2) {
        if (!cache_resizeapp(c, c->size*2)) {
            pthread_mutex_unlock(&c->mux);
            return;
        }
    }

    unsigned long hash = hashStr(app);
    cache_putapp_hash(c, hash, passwd);

    pthread_mutex_unlock(&c->mux);
}

int cache_getapp(struct cache_ap *c, unsigned char *app, unsigned char **passwd)
{
    pthread_mutex_lock(&c->mux);
#if DBG_CACHE
    cache_printapp(c);
#endif
    unsigned long hash = hashStr(app);
    size_t id;
    for (id = hash % c->size; c->map[id].appkey != 0; id = (id+1) % c->size)
        if (c->map[id].appkey == hash) {
            *passwd = pl->mystrdup(c->map[id].passwd);
            dbg_cache("%s lookup success: size:%lu, elemnts:%lu, id:%lu, key:{%lu,%s}, val:%s\n", __func__,
                    c->size, c->elements, id, hash, app, c->map[id].passwd);
            pthread_mutex_unlock(&c->mux);
            return 1;
        }
    dbg_cache("%s lookup fail: size:%lu, elemnts:%lu, id:%lu, key:{%lu,%s}, val:%s\n", __func__,
            c->size, c->elements, id, hash, app, c->map[id].passwd);
    pthread_mutex_unlock(&c->mux);
    return 0;
}

int cache_initip(struct cache_ip *c, size_t initsize)
{
    if (initsize < 1){
        fprintf(stderr, "%s: cache_ip init size should be >= 1, provided size: %lu\n", __func__, initsize);
        return 0;
    }
    c->elements = 0;
    c->size = initsize;
    c->map = pl->myalloc(initsize * sizeof(*c->map));
    if (!c->map) {
        fprintf(stderr, "%s: oom can't alloc", __func__);
        return 0;
    }
    memset(c->map, 0, c->size * sizeof(*c->map));
    pthread_mutex_init(&c->mux, NULL);
    return 1;
}

int cache_initapp(struct cache_ap *c, size_t initsize)
{
    if (initsize < 1) {
        fprintf(stderr, "%s: cache_ap init size should be >= 1, provided size: %lu\n", __func__, initsize);
        return 0;
    }
    c->elements = 0;
    c->size = initsize;
    c->map = pl->myalloc(c->size * sizeof(*c->map));
    if (!c->map) {
        fprintf(stderr, "%s: oom can't alloc", __func__);
        return 0;
    }
    memset(c->map, 0, initsize * sizeof(*c->map));
    pthread_mutex_init(&c->mux, NULL);
    return 1;
}

static void cache_printip(struct cache_ip *c)
{
    int i;
    printf("cache_ip.size: %lu\n", c->size);
    printf("cache_ip.elements: %lu\n", c->elements);
    for (i=0; i < c->size; i++){
        printf("%d: key:%u, val:{%s,%s}\n", i, c->map[i].ipkey, c->map[i].user, c->map[i].passwd);
    }
}

static void cache_printapp(struct cache_ap *c)
{
    int i;
    printf("cache_app.size: %lu\n", c->size);
    printf("cache_app.elements: %lu\n", c->elements);
    for(i=0; i < c->size; i++){
        printf("%d: key:%lu, val:%s\n", i, c->map[i].appkey, c->map[i].passwd);
    }
}
