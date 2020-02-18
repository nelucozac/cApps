/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
 There is NO WARRANTY, to the extent permitted by applicable law.
 Header file, list of data type definitions and predefined functions.
 See attached documentation for details.
 Author: nelu.cozac@gmail.com
*/

#ifndef _C_application_server_h

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define _C_application_server_h

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#include <stdarg.h>

#include <poll.h>
#include <sys/resource.h>
#include <sys/sendfile.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <signal.h>
#include <limits.h>

#include <sys/syscall.h>
#include <linux/futex.h>

#ifdef _Secure_application_server
#define _Release_application_server
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define endOfString(S, k) ((S) + (strlen(S) + (k)))

typedef struct {
        unsigned char Ipc[16];
        long double tim;
        time_t uts;
        char *Bfi, *Bfo, *Bft;
        char *Pct, *Pet;
        char Ufn[4];
        volatile char tmo;
        void *Usr, *Ssn;
        } SRV_conn;

typedef struct {
        int af;
        char **Rh;
        char *Nv;
        int ss, se, fs;
        void (*data)(char), (*html)(char);
        void (*cnfg)(char *), (*preq)(SRV_conn *), (*rwrl)(SRV_conn *);
        int (*acco)(unsigned char *), (*post)(SRV_conn *, int, int);
        } SRV_info;
extern SRV_info Srvinfo;

typedef struct {
        char Sid[12];
        unsigned char Ipc[16];
        long long etm;
        } SSN_info;

long double getTime(SRV_conn *Conn);

int explodeHtm(char *Htmi, void *Htmo, int siz),
    serverMutex(SRV_conn *Conn, int *Mtx, char op);

char *getParamName(SRV_conn *Conn, char *From),
     *getParamValue(SRV_conn *Conn, char *Name, char *From),
     *getLastParamValue(SRV_conn *Conn, char *Name),
     *getHeaderName(SRV_conn *Conn, char *From),
     *getHeaderValue(SRV_conn *Conn, char *Name),
     *convertString(SRV_conn *Conn, char *Str, char mod),
     *cPrintf(SRV_conn *Conn, char *Fmt, ...),
     *loadTextFile(char *Nft),
     *buildMimeTypeList(char *Cfg);

#define getThisParamValue(Conn, Pnam) (Pnam + strlen(Pnam) + 1)

void sendContentToClient(SRV_conn *Conn, char *Nft, char *Rhf, void *Buf, int siz),
     sendFileToClient(SRV_conn *Conn, char *Nft, char *Rhf, int (*valid)(char *)),
     nPrintf(SRV_conn *Conn, char *Fmt, ...),
     resetOutputBuffer(SRV_conn *Conn),
     registerUserSettings(void);

void newSession(SRV_conn *Conn),
     checkSession(SRV_conn *Conn, char *Sid),
     closeSession(SRV_conn *Conn, char *Sid);

/* The following functions are for internal use */
void convertBinaryToName(char *Nam, int np, unsigned long long val),
     initSessions(char *Sfn),
     writeSession(SRV_conn *Conn);
/* and should not be called by developers */

#endif
