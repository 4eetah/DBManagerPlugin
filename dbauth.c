#include "structures.h"
#include "db.h"
#include <string.h>
#include <assert.h>

struct pluginlink *pl;
static struct auth dbappauth;
static char plugname[] = "DBManagerPlugin";

int (*redirfunc)(struct clientparam * param, struct ace * acentry);

/* user-chainip-chainport */
int socks_chainaddr(char *buf, char chainip[16], char chainport[6])
{
    char *saveptr;

    if (!(buf = strtok_r(buf, "-", &saveptr)))
        return 0;
    if (!(buf = strtok_r(NULL, "-", &saveptr)))
        return 0;
    strncpy(chainip, buf, 15);
    chainip[15] = 0;

    if (!(buf = strtok_r(NULL, "-", &saveptr)))
        return 0;
    strncpy(chainport, buf, 5);
    chainport[5] = 0;

    return 1;
}

static int dbappauthfunc(struct clientparam *param)
{
    unsigned char appuser[256];
    unsigned char *endptr, *apppasswd;
    int usrlen;

    if(!param->username || !param->password)
        return 4;

    endptr = strchr(param->username, '-');
    if (!endptr) {
        fprintf(stderr, "error, can't extract app user, required format: appuser-xx.xx.xx.xx-xx:apppasswd, provided: %s\n", param->username);
        return 4;
    }
    usrlen = endptr - param->username;
    memcpy(appuser, param->username, usrlen);
    appuser[usrlen] = 0;

    if (!cache_getapp(appuser, &apppasswd)) {
        if ((apppasswd = sqlget_apppasswd(appuser)) == NULL) {
            fprintf(stderr, "unable to dbget app passwd for user: %s\n", appuser);
            return 5;
        }
        cache_putapp(appuser, apppasswd);
    }

    if (strcmp(param->password, apppasswd) != 0) {
        fprintf(stderr, "wrong password, provided: %s, expected: %s\n", param->password, apppasswd);
        return 6;
    }

    return 0;
}

static int checkACLandRedir(struct clientparam *param)
{
    int ret;
    struct ace nextace;
    struct chain nextchain;
    char chainip[16], chainport[6];
    unsigned char *proxyuser, *proxypasswd;
    char *err;
    unsigned int proxyip;
    unsigned short proxyport;

    /* Check ACL */ 
    ret = pl->checkACL(param);
    if (ret != 0)
        return ret;

    /* Redirect */

    /* some err code because we've been already redirected with the static
     * route from the srv conf */
    if (param->redirected)
        return 3;

    /* some err code, we don't have a valid chain specifier in the
     * provided socks username */
    if (!socks_chainaddr(param->username, chainip, chainport)) {
        fprintf(stderr, "%s: error, bad proxy ip address provided %s\n", __func__, chainip);
        return 3;
    }

    memset(&nextace, 0, sizeof(nextace));
    memset(&nextchain, 0, sizeof(nextchain));

    nextace.chains = &nextchain;
    /* fill int next chain */
    nextchain.weight = 1000;
    nextchain.exthost = chainip;
    nextchain.type = R_SOCKS5;

    /* we can pull out family from database to support ipv4/ipv6 */
    *SAFAMILY(&nextchain.addr) = AF_INET;
    if (inet_pton(*SAFAMILY(&nextchain.addr), chainip, SAADDR(&nextchain.addr)) != 1) {
        fprintf(stderr, "%s: can't inet_pton provided proxy ip address %s\n", __func__, chainip);
        return 3;
    }
    proxyport = strtol(chainport, &err, 10);
    if (*err) {
        fprintf(stderr, "%s: bad proxy port provided %s\n", __func__, chainport);
        return 3;
    }
    *SAPORT(&nextchain.addr) = htons(proxyport);

    /* get user/passwd for chainip:chainport proxy from db */
    proxyip = ntohl(((struct sockaddr_in *)&nextchain.addr)->sin_addr.s_addr);
    if (!cache_getip(proxyip, &proxyuser, &proxypasswd)) {
        if (sqlget_proxycreds(&proxyuser, &proxypasswd, proxyip, proxyport, 1) == -1) {
            fprintf(stderr, "unable to dbget user/passwd for the given proxy server: %s:%d", chainip, proxyport);
            return 5;
        }
        cache_putip(proxyip, proxyuser, proxypasswd);
    }
    nextchain.extuser = proxyuser;
    nextchain.extpass = proxypasswd;

    ret = redirfunc(param, &nextace);

    pl->myfree(proxyuser);
    pl->myfree(proxypasswd);

    return ret;
}

PLUGINAPI int PLUGINCALL start(struct pluginlink * pluginlink, int argc, unsigned char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "%s, usage: plugin /path/to/DBManagerPlugin.ld.so start odbcsource,user,passwd\n", plugname);
        return 1;
    }
    if (sqlinit(argv[1]) == -1) {
        fprintf(stderr, "%s, can't initialize database, provided db info: %s\n", plugname, argv[1]);
        return 1;
    }

    pl = pluginlink;

    dbappauth.authenticate = dbappauthfunc;
    dbappauth.authorize = checkACLandRedir;
    dbappauth.desc = "dbappauth";
    dbappauth.next = pl->authfuncs->next;
    pl->authfuncs->next = &dbappauth;
    redirfunc = pl->findbyname("handleredirect");
    cache_ipinit(&map_ip);
    cache_appinit(&map_app);

    return 0;
}
