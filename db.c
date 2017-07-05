#include <sqltypes.h>
#include <sql.h>
#include <sqlext.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "db.h"

SQLHENV henv = NULL;
SQLHDBC hdbc = NULL;

static void extract_error(char *fn, SQLHANDLE handle, SQLSMALLINT type)
{
    SQLINTEGER   i = 0;
    SQLINTEGER   native;
    SQLCHAR  state[ 7 ];
    SQLCHAR  text[256];
    SQLSMALLINT  len;
    SQLRETURN    ret;

    fprintf(stderr,
            "\n"
            "The driver reported the following diagnostics whilst running "
            "%s\n\n",
            fn);

    do {
        ret = SQLGetDiagRec(type, handle, ++i, state, &native, text,
                            sizeof(text), &len);
        if (SQL_SUCCEEDED(ret))
            printf("%s:%ld:%ld:%s\n", state, i, (long)native, text);
    }
    while(ret == SQL_SUCCESS);
}

void sqlclose()
{
	if(hdbc){
		SQLDisconnect(hdbc);
		SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
		hdbc = NULL;
	}
	if(henv) {
		SQLFreeHandle(SQL_HANDLE_ENV, henv);
		henv = NULL;
	}
}

int sqlinit(char * s)
{
	SQLRETURN retcode;
	char *datasource;
	char *username;
	char *password;

    if (!s)
        return -1;

	if(hdbc || henv)
        sqlclose();

	if(!henv){
		retcode = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &henv);
		if (!henv || (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO)){
			henv = NULL;
			return -1;
		}
		retcode = SQLSetEnvAttr(henv, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0);

		if (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO) {
			return -1;
		}
	}
	if(!hdbc){
		retcode = SQLAllocHandle(SQL_HANDLE_DBC, henv, &hdbc);
		if (!hdbc || (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO)) {
			hdbc = NULL;
			SQLFreeHandle(SQL_HANDLE_ENV, henv);
			henv = NULL;
			return -1;
		}
	    SQLSetConnectAttr(hdbc, SQL_LOGIN_TIMEOUT, (void*)15, 0);
	}
	datasource = strtok(s, ",");
	username = strtok(NULL, ",");
	password = strtok(NULL, ",");

    retcode = SQLConnect(hdbc, (SQLCHAR*)datasource, (SQLSMALLINT)strlen(datasource),
            (SQLCHAR*)username, (SQLSMALLINT)((username)?strlen(username):0),
            (SQLCHAR*)password, (SQLSMALLINT)((password)?strlen(password):0));

	if (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO){
		SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
		hdbc = NULL;
		SQLFreeHandle(SQL_HANDLE_ENV, henv);
		henv = NULL;
		return -1;
	}

	return 0;
}

char *sqlget_apppasswd(unsigned char *appuser)
{
    if (!henv || !hdbc) {
        fprintf(stderr, "DB isn't initialized");
        return NULL;
    }

    SQLHSTMT mystmt = NULL;
    SQLRETURN ret;
    SQLCHAR passwd[256];

    ret = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &mystmt);
    if (!SQL_SUCCEEDED(ret)) {
        extract_error("dbappauth: SQLAllocHandle mystmt", mystmt, SQL_HANDLE_STMT);
        goto error;
    }

    ret = SQLBindCol(mystmt, 1, SQL_C_CHAR, passwd, sizeof(passwd), NULL);
    if (!SQL_SUCCEEDED(ret)) {
        extract_error("dbappauth: SQLBindCol passwd", mystmt, SQL_HANDLE_STMT);
        goto error;
    }

    ret = SQLBindParameter(mystmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 255, 0, appuser, 255, NULL);
    if (!SQL_SUCCEEDED(ret)) {
        extract_error("dbappauth: SQLBindParameter username", mystmt, SQL_HANDLE_STMT);
        goto error;
    }

    ret = SQLExecDirect(mystmt, "SELECT pass FROM app WHERE user = ?", SQL_NTS);
    if (!SQL_SUCCEEDED(ret)) {
        extract_error("dbappauth: SQLExecDirect", mystmt, SQL_HANDLE_STMT);
        goto error;
    }

    ret = SQLFetch(mystmt);
    if (ret == SQL_NO_DATA) {
        fprintf(stderr, "dbappauth: Specified `user`(%s) not found in `app` table\n", appuser);
        goto error;
    } else if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        extract_error("dbappauth: SQLFetch error", mystmt, SQL_HANDLE_STMT);
        goto error;
    }


    SQLFreeHandle(SQL_HANDLE_STMT, mystmt);
    return pl->mystrdup(passwd);

error:
    SQLFreeHandle(SQL_HANDLE_STMT, mystmt);
    return NULL;
}

/* get user/passwd for the given (ip, port) in host byte order + status */
int sqlget_proxycreds(unsigned char **puser, unsigned char **ppasswd, unsigned int ip, unsigned short port, unsigned int status)
{
    if (!henv || !hdbc) {
        fprintf(stderr, "DB isn't initialized\n");
        return -1;
    }

    SQLHSTMT mystmt = NULL;
    SQLRETURN ret;
    SQLCHAR user[256], passwd[256];

    ret = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &mystmt);
    if (!SQL_SUCCEEDED(ret)) {
        extract_error("dbget_credentials: SQLAllocHandle mystmt", mystmt, SQL_HANDLE_STMT);
        return -1;
    }

    ret = SQLBindCol(mystmt, 1, SQL_C_CHAR, user, sizeof(user), NULL);
    if (!SQL_SUCCEEDED(ret)) {
        extract_error("dbget_credentials: SQLBind user", mystmt, SQL_HANDLE_STMT);
        goto error;
    }
    ret = SQLBindCol(mystmt, 2, SQL_C_CHAR, passwd, sizeof(passwd), NULL);
    if (!SQL_SUCCEEDED(ret)) {
        extract_error("dbget_credentials: SQLBind passwd", mystmt, SQL_HANDLE_STMT);
        goto error;
    }

    ret = SQLBindParameter(mystmt, 1, SQL_PARAM_INPUT, SQL_C_ULONG, SQL_INTEGER, sizeof(ip), 0, &ip, sizeof(ip), NULL);
    if (!SQL_SUCCEEDED(ret)) {
        extract_error("dbget_credentials: SQLBindParameter ip", mystmt, SQL_HANDLE_STMT);
        goto error;
    }
    ret = SQLBindParameter(mystmt, 2, SQL_PARAM_INPUT, SQL_C_USHORT, SQL_SMALLINT, sizeof(port), 0, &port, sizeof(port), NULL);
    if (!SQL_SUCCEEDED(ret)) {
        extract_error("dbget_credentials: SQLBindParameter port", mystmt, SQL_HANDLE_STMT);
        goto error;
    }
    ret = SQLBindParameter(mystmt, 3, SQL_PARAM_INPUT, SQL_C_ULONG, SQL_INTEGER, sizeof(status), 0, &status, sizeof(status), NULL);
    if (!SQL_SUCCEEDED(ret)) {
        extract_error("dbget_credentials: SQLBindParameter status", mystmt, SQL_HANDLE_STMT);
        goto error;
    }

    ret = SQLExecDirect(mystmt, "SELECT user, pass FROM proxy WHERE ip = ? and port = ? and status = ?", SQL_NTS);
    if (!SQL_SUCCEEDED(ret)) {
        extract_error("dbget_credentials: SQLExecDirect select user, pass", mystmt, SQL_HANDLE_STMT);
        goto error;
    }

    ret = SQLFetch(mystmt);
    if (ret == SQL_NO_DATA) {
        fprintf(stderr, "Specified `ip`(%u),`port`(%u),`status`(%d) not found in `proxy` table\n", ip, port, status);
        goto error;
    } else if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        extract_error("dbget_credentials: SQLFetch", mystmt, SQL_HANDLE_STMT);
        goto error;
    }

    *puser = pl->mystrdup(user);
    *ppasswd = pl->mystrdup(passwd);
    SQLFreeHandle(SQL_HANDLE_STMT, mystmt);

    return 0;

error:
    SQLFreeHandle(SQL_HANDLE_STMT, mystmt);
    return -1;
}
