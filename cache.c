#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "structures.h"
#include "db.h"

#define MAPIP_SIZE (1 << 16)
#define MAPAPP_SIZE (1 << 10)

struct map_ip2creds map_ip;
struct map_app2pass map_app;

#define idx_ipmap(n) (((size_t)(n)) % map_ip.size)
#define idx_appmap(n) (((size_t)(n)) % map_app.size)

/* Robert Jenkins' 32 bit integer hash function */
uint32_t hash32(uint32_t a)
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
unsigned long hashStr(unsigned char *str)
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c;

    return hash;
}

void cache_putip(uint32_t key, unsigned char *user, unsigned char *passwd)
{
    pthread_mutex_lock(&map_ip.mux);
    size_t id;
    for (id = idx_ipmap(hash32(key)); map_ip.map[id].ipkey != 0; id = idx_ipmap(id+1))
        if (map_ip.map[id].ipkey == key)
            break;

    if (map_ip.map[id].ipkey != 0) {
        pl->myfree(map_ip.map[id].user);
        pl->myfree(map_ip.map[id].passwd);
    } else {
        map_ip.elements++;
    }
    map_ip.map[id].ipkey = key;
    map_ip.map[id].user = pl->mystrdup(user);
    map_ip.map[id].passwd = pl->mystrdup(passwd);

    if (map_ip.elements >= (map_ip.size>>1)) {
        fprintf(stderr, "%s: realloc from %lu to %lu\n", __func__, map_ip.size, map_ip.size<<1);
        void *p = pl->myalloc(map_ip.size<<1 * sizeof(*map_ip.map));
        memset(p, 0, map_ip.size<<1 * sizeof(*map_ip.map));
        memmove(p, map_ip.map, map_ip.size * sizeof(*map_ip.map));
        pl->myfree(map_ip.map);
        map_ip.map = p;
        map_ip.size <<= 1;
    }
    pthread_mutex_unlock(&map_ip.mux);
}

int cache_getip(uint32_t key, unsigned char **user, unsigned char **passwd)
{
    pthread_mutex_lock(&map_ip.mux);
    size_t id;
    for (id = idx_ipmap(hash32(key)); map_ip.map[id].ipkey != 0; id = idx_ipmap(id+1))
        if (map_ip.map[id].ipkey == key) {
            *user = pl->mystrdup(map_ip.map[id].user);
            *passwd = pl->mystrdup(map_ip.map[id].passwd);
            pthread_mutex_unlock(&map_ip.mux);
            return 1;
        }
    pthread_mutex_unlock(&map_ip.mux);
    return 0;
}

void cache_putapp(unsigned char *app, unsigned char *passwd)
{
    pthread_mutex_lock(&map_app.mux);
    unsigned long hash = hashStr(app);
    size_t id;
    for (id = idx_appmap(hash); map_app.map[id].appkey != 0; id = idx_appmap(id+1))
        if (map_app.map[id].appkey == hash)
            break;
    
    if (map_app.map[id].appkey != 0) {
        pl->myfree(map_app.map[id].passwd);
    } else {
        map_app.elements++;
    }
    map_app.map[id].appkey = hash;
    map_app.map[id].passwd = pl->mystrdup(passwd);

    if (map_app.elements >= (map_app.size>>1)) {
        void *p = pl->myalloc(map_app.size<<1 * sizeof(*map_app.map));
        memset(p, 0, map_app.size<<1 * sizeof(*map_app.map));
        memmove(p, map_app.map, map_app.size * sizeof(*map_app.map));
        pl->myfree(map_app.map);
        map_app.map = p;
        map_app.size <<= 1;
    }
    pthread_mutex_unlock(&map_app.mux);
}

int cache_getapp(unsigned char *app, unsigned char **passwd)
{
    pthread_mutex_lock(&map_app.mux);
    unsigned long hash = hashStr(app);
    size_t id;
    for (id = idx_appmap(hash); map_app.map[id].appkey != 0; id = idx_appmap(id+1))
        if (map_app.map[id].appkey == hash) {
            *passwd = pl->mystrdup(map_app.map[id].passwd);
            pthread_mutex_unlock(&map_app.mux);
            return 1;
        }
    pthread_mutex_unlock(&map_app.mux);
    return 0;
}

int cache_ipinit(struct map_ip2creds *map)
{
    map->elements = 0;
    map->size = MAPIP_SIZE;
    map->map = pl->myalloc(map->size * sizeof(*map->map));
    memset(map->map, 0, map->size * sizeof(*map->map));
    pthread_mutex_init(&map->mux, NULL);
}

int cache_appinit(struct map_app2pass *map)
{
    map->elements = 0;
    map->size = MAPAPP_SIZE;
    map->map = pl->myalloc(map->size * sizeof(*map->map));
    memset(map->map, 0, map->size * sizeof(*map->map));
    pthread_mutex_init(&map->mux, NULL);
}
