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

struct map_ip2creds {
    size_t elements;
    size_t size;
    struct ip2creds *map;
    pthread_mutex_t mux;
};

struct map_app2pass {
    size_t elements;
    size_t size;
    struct app2passwd *map;
    pthread_mutex_t mux;
};

void sqlclose();
int sqlinit(char * s);
char *sqlget_apppasswd(unsigned char *appuser);
int sqlget_proxycreds(unsigned char **puser, unsigned char **ppasswd, unsigned int ip, unsigned short port, unsigned int status);

int cache_ipinit(struct map_ip2creds *map);
int cache_appinit(struct map_app2pass *map);
void cache_putip(uint32_t key, unsigned char *user, unsigned char *passwd);
void cache_putapp(unsigned char *app, unsigned char *passwd);
int cache_getip(uint32_t key, unsigned char **user, unsigned char **passwd);
int cache_getapp(unsigned char *app, unsigned char **passwd);

#endif //DB_H
