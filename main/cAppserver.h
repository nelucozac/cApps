/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
 There is NO WARRANTY, to the extent permitted by applicable law.
 Header file, list of data type definitions and predefined functions.
 See attached documentation for details.
 Author: nelu.cozac@gmail.com
*/

#ifndef _C_application_server_h

#define _C_application_server_h
#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#include <pthread.h>
#include <stdarg.h>

#include <poll.h>
#include <sys/resource.h>
#include <sys/sendfile.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <signal.h>
#include <limits.h>

#define CAS_endOfString(S, k) ((S) + (strlen(S) + (k)))

typedef struct {
        unsigned char Ipc[16];
        time_t uts;
        char *Bfi, *Bfo, *Bft;
        char *Pct, *Pet;
        char Ufn[4];
        void *Usr, *Ssn;
        } CAS_srvconn_t;

typedef struct {
        int af;
        char **Rh;
        char *Nv;
        int fs, ss, se, ns;
        void (*data)(char), (*html)(char);
        void (*cnfg)(char *), (*preq)(CAS_srvconn_t *), (*rwrl)(CAS_srvconn_t *);
        int (*acco)(unsigned char *), (*post)(CAS_srvconn_t *, int, int);
        } CAS_srvinfo_t;
extern CAS_srvinfo_t CAS_Srvinfo;

void CAS_registerUserSettings(void);

double CAS_getTime(CAS_srvconn_t *Conn);

int CAS_explodeHtm(char *Htmi, void *Htmo, int siz);

char *CAS_getParamName(CAS_srvconn_t *Conn, char *From),
     *CAS_getParamValue(CAS_srvconn_t *Conn, char *Name, char *From),
     *CAS_getLastParamValue(CAS_srvconn_t *Conn, char *Name),
     *CAS_getHeaderName(CAS_srvconn_t *Conn, char *From),
     *CAS_getHeaderValue(CAS_srvconn_t *Conn, char *Name),
     *CAS_convertString(CAS_srvconn_t *Conn, char *Str, char mod),
     *CAS_sPrintf(CAS_srvconn_t *Conn, char *Fmt, ...),
     *CAS_loadTextFile(char *Nft),
     *CAS_buildMimeTypeList(char *Cfg);

void CAS_multithreading(CAS_srvconn_t *Conn, char opt);

#define CAS_getThisParamValue(Conn, Pnam) (Pnam + strlen(Pnam) + 1)

void CAS_sendContentToClient(CAS_srvconn_t *Conn, char *Nft, char *Rhf, void *Buf, int siz),
     CAS_sendFileToClient(CAS_srvconn_t *Conn, char *Nft, char *Rhf, int (*valid)(char *)),
     CAS_nPrintf(CAS_srvconn_t *Conn, char *Fmt, ...),
     CAS_resetOutputBuffer(CAS_srvconn_t *Conn);

void CAS_createSession(CAS_srvconn_t *Conn),
     CAS_checkSession(CAS_srvconn_t *Conn, char *Sva),
     CAS_deleteSession(CAS_srvconn_t *Conn, char *Sva);

/* The following functions have been developed for internal use */
void CAS_convertBinaryToName(char *Nam, int np, unsigned long long val),
     CAS_updateSession(CAS_srvconn_t *Conn),
     CAS_initSessionSupport(char *Sfn);

#endif
