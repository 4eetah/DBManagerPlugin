#ifndef DB_H
#define DB_H

#include <stdint.h>
#include "structures.h"

extern struct map_ip2creds map_ip;
extern struct map_app2pass map_app;
extern struct pluginlink *pl;

struct ip2creds {
    uint32_t ipkey;
    unsigned char *user;
    unsigned char *passwd;
};
struct app2passwd {
    unsigned long appkey;
    unsigned char *passwd;
};

struct cache_ip {
    size_t elements;
    size_t size;
    struct ip2creds *map;
    pthread_mutex_t mux;
};
struct cache_ap {
    size_t elements;
    size_t size;
    struct app2passwd *map;
    pthread_mutex_t mux;
};

void sqlclose();
int sqlinit(char * s);
char *sqlget_apppasswd(unsigned char *appuser);
int sqlget_proxycreds(unsigned char **puser, unsigned char **ppasswd, unsigned int ip, unsigned short port, unsigned int status);

static int cache_resizeip(struct cache_ip *c, size_t newsize);
void cache_putip(struct cache_ip *c, uint32_t key, unsigned char *user, unsigned char *passwd);
int cache_getip(struct cache_ip *c, uint32_t key, unsigned char **user, unsigned char **passwd);
static int cache_resizeapp(struct cache_ap *c, size_t newsize);
void cache_putapp(struct cache_ap *c, unsigned char *app, unsigned char *passwd);
static void cache_putapp_hash(struct cache_ap *c, unsigned long hash, unsigned char *passwd);
int cache_getapp(struct cache_ap *c, unsigned char *app, unsigned char **passwd);
int cache_initip(struct cache_ip *c, size_t initsize);
static void cache_printip(struct cache_ip *c);
static void cache_printapp(struct cache_ap *c);

#endif //DB_H
