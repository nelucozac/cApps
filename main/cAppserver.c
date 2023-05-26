/*
 Copyright (C) 2019 Nelu Cozac
 
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
 There is NO WARRANTY, to the extent permitted by applicable law.
 The web server application will accept GET, POST and LOAD requests.
 For enctype, only application/x-www-form-urlencoded is accepted.
 Use LOAD method to upload files.
 See attached documentation for details.
 The secure version is based on Openssl library <https://www.openssl.org>
 Author: nelu.cozac@gmail.com
*/

#include "cAppserver.h"
#ifdef _Secure_application_server
#define _Release_application_server
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#endif

typedef struct {
        CAS_srvconn_t Co;
        #ifdef _Secure_application_server
        SSL *Ss;
        #endif
        union { pthread_t td; long long id; } ;
        int mt, mi, sk;
        char *Bf, *Pm, *Hm, *Po, *Ei;
        time_t us;
        signed char cs;
        char rq, xc;
        } T_threadinfo;

CAS_srvinfo_t CAS_Srvinfo;

static char *Mssg[] = { "--start", "--stop", "--cnfg", "--data", "--html", "--show", NULL, "--wait", "--essn" } ;
static char *Okdt = "Ok data";

static struct {
       int stks, sBfi, sBfo, sBft;
       int lsa, norp, lbf, lpw, Lpo[2];
       int pto, err, nls, Dsk[2];
       int *Wstk;
       pthread_t tid;
       char *Pswd, *Pcfg, *Nprg, Ncfg[4096];
       char Buf[4096], Herr[256], *Mtl;
       unsigned char Lhst[16];
       struct timeval Trcv;
       struct rlimit Rlim;
       union { struct sockaddr_in Sao; struct sockaddr_in6 San; } ;
       struct pollfd Pof[2];
       sigset_t Pmsk, Wmsk;
       pthread_attr_t Attr;
       void *Psa;
       char req, psu, stkT;
       } Srvcfg;

static struct {
       T_threadinfo *Cl;
       int nc;
       } Lsthread;

static void errorMessage(char *, int);

#ifdef _Secure_application_server

static struct {
       char Nkey[4096];
       SSL_METHOD *Mtd;
       SSL_CTX *Ctx;
       X509 *Ctf;
       RSA *Rsa;
       } Secinf;

static char *Ectx = "Create SSL_CTX object";

static char *secureError(T_threadinfo *Thrd, char *Op) {
char *Er;
int k,l;
Er = Thrd->Co.Pct;
l = 0;
do {
   k = ERR_get_error();
   if (k==0) break;
   if (l++>0) continue;
   Thrd->Co.Pct = Er + sprintf(Er,"%s - %s",Op,ERR_reason_error_string(k)) + 1;
   } while (1);
return Er;
}

static void errorCertificate(char *Me) {
int s;
sprintf(Srvcfg.Buf,"0000/00/00 00:00 - %s: %s\n",Me,ERR_reason_error_string(ERR_get_error()));
if (Srvcfg.err>0) s = write(Srvcfg.err,Srvcfg.Buf,strlen(Srvcfg.Buf));
fputs(Srvcfg.Buf,stderr);
exit(1);
}

static void readCertificate(void) {
char *Pem,*Cbf,*Kbf;
BIO *Bio;
Secinf.Ctx = SSL_CTX_new(Secinf.Mtd);
if (Secinf.Ctx==NULL) errorCertificate(Ectx);
Pem = CAS_loadTextFile(Secinf.Nkey);
for (Cbf=Pem; isspace(*Cbf); Cbf++) ;
Kbf = strstr(Cbf," RSA ");
if (Kbf==NULL) {
   strcat(Secinf.Nkey," file error: wrong content or RSA key not found");
   errorMessage(Secinf.Nkey,0);
   }
while (*Kbf!='\n') Kbf--;
Bio = BIO_new_mem_buf(Cbf,-1);
if (Bio==NULL)
   errorCertificate("Create memory Bio (certificate)");
Secinf.Ctf = PEM_read_bio_X509(Bio,NULL,0,NULL);
if (Secinf.Ctf==NULL)
   errorCertificate("Read certificate from Bio");
if (SSL_CTX_use_certificate(Secinf.Ctx,Secinf.Ctf)<=0)
   errorCertificate("Use certificate");
free(Bio);
Bio = BIO_new_mem_buf(Kbf+1,-1);
if (Bio==NULL)
   errorCertificate("Create memory Bio (private key)");
Secinf.Rsa = PEM_read_bio_RSAPrivateKey(Bio,NULL,0,NULL);
if (Secinf.Rsa==NULL)
   errorCertificate("Read private key from Bio");
if (SSL_CTX_use_RSAPrivateKey(Secinf.Ctx,Secinf.Rsa)<=0)
   errorCertificate("Use private key");
free(Bio);
if (SSL_CTX_check_private_key(Secinf.Ctx)!=1)
   errorCertificate("Certificate and private key don't match");
free(Pem);
SSL_CTX_set_mode(Secinf.Ctx,SSL_MODE_AUTO_RETRY);
}

static int redirectToHttps(T_threadinfo *Thrd) {
char *Bi,*Bf,*Pa,c;
int l,p;
if (CAS_Srvinfo.Rh[2]==NULL) return 404;
Bi = Thrd->Bf + 4;
do {
   c = *++Bi;
   if (c==0) return 404;
   if (isspace(c)) break;
   } while (1);
if (Bi-Thrd->Bf==5) Bi--;
*Bi++ = 0;
Bf = Thrd->Bf + 4;
l = strlen(Bf) + 1;
Pa = Thrd->Bf + Srvcfg.sBfo - l;
memcpy(Pa,Bf,l);
do {
   do {
      c = *Bi++;
      if (c==0) return 404;
      if (c=='\r') break;
      if (c=='\n') break;
      } while (1);
   do {
      if (isspace(c)) break;
      if (c==0) return 404;
      c = *Bi++;
      } while (1);
   if (strncasecmp(Bi,"Host:",5)!=0) continue;
   Bi += 5;
   if (isspace(*Bi)==0) return 404;
   while (isspace(*Bi)) Bi++;
   Bf = Bi;
   do {
      c = *++Bf;
      if (c==0) break;
      if (isspace(c) || (c==':')) {
         *Bf = 0;
         break;
         }
      } while (1);
   Bf = Thrd->Bf + 4;
   break;
   } while (1);
Bf = Thrd->Bf;
l = strlen(Bi);
memmove(Bf,Bi,l);
p = Srvcfg.Lpo[1];
if (p!=443) {
   sprintf(Bf+l,":%d",p);
   l = strlen(Bf);
   }
Pa -= l;
memcpy(Pa,Bf,l);
CAS_nPrintf(&Thrd->Co,CAS_Srvinfo.Rh[2],Pa);
return 301;
}

#endif

void CAS_resetOutputBuffer(CAS_srvconn_t *Conn) {
((T_threadinfo *)Conn)->Po = Conn->Bfo;
}

void CAS_convertBinaryToName(char *Nam, int np, unsigned long long val) {
static char Dgts[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_";
static int m = 63;
int l;
for (l=np-1,Nam[np]=0; l>=0; l--) {
    Nam[l] = Dgts[val%m];
    val /= m;
    }
}

static char *whichMessage(char c) {
static char *Smsg = "-ZCDHS-W";
if (c=='E') return Mssg[8];
return Mssg[strchr(Smsg,c)-Smsg];
}

static int checkAdminRequest(CAS_srvconn_t *Conn) {
char *Bf,c;
if (memcmp(Conn->Ipc,Srvcfg.Lhst,CAS_Srvinfo.af==AF_INET?4:16)!=0)
   return 404;
Bf = strchr(Conn->Bfi,' ');
if (Bf==NULL) return 404;
Bf++;
if (memcmp(Bf,Srvcfg.Pswd,Srvcfg.lpw)!=0) return 404;
c = Bf[Srvcfg.lpw];
if (c) if (c!=' ') return 404;
Bf = Conn->Bfi;
if (memcmp(Bf,Mssg[2],6)==0) return 'C';
if (memcmp(Bf,Mssg[3],6)==0) return 'D';
if (memcmp(Bf,Mssg[4],6)==0) return 'H';
if (memcmp(Bf,Mssg[5],6)==0) return 'S';
if (memcmp(Bf,Mssg[7],6)==0) return 'W';
if (memcmp(Bf,Mssg[8],6)==0) return 'E';
if (memcmp(Bf,Mssg[1],6)==0) return 'Z';
return 404;
}

static void deleteExpiredSession(CAS_srvconn_t *Conn) {
struct { char *Sv; time_t et; } Essn;
Essn.Sv = strchr(Conn->Bfi,' ') + 1;
Essn.Sv = strchr(Essn.Sv,' ') + 1;
Essn.et = 0;
Conn->Ssn = &Essn;
CAS_updateSession(Conn);
}

static int recvFromClient(T_threadinfo *Thrd, void *Buf, int len) {
#ifdef _Secure_application_server
int s;
if (Thrd->cs>0) {
   s = SSL_read(Thrd->Ss,Buf,len);
   return s;
   }
#endif
return recv(Thrd->sk,Buf,len,0);
}

static void sendToClient(CAS_srvconn_t *Conn, char *Bf, int ls) {
T_threadinfo *Thrd;
int s;
Thrd = (T_threadinfo *)Conn;
if (Bf==NULL) {
   Bf = Conn->Bfo;
   ls = Thrd->Po - Bf;
   }
if (ls>0) {
   do {
      #ifdef _Secure_application_server
      if (Thrd->cs>0) {
         s = SSL_write(Thrd->Ss,Bf,ls);
         if (s<0) secureError(Thrd,"");
         }
      else
      #endif
      s = send(Thrd->sk,Bf,ls,0);
      if (s==ls) break;
      if (s<=0) break;
      Bf += s;
      ls -= s;
      } while (1);
   memset(Conn->Bfo,0,Conn->Bft-Conn->Bfo);
   Thrd->Po = Conn->Bfo;
   }
}

char *CAS_buildMimeTypeList(char *Cfg) {
char *Pd,c,w;
while (isspace(*Cfg)) Cfg++;
Srvcfg.Mtl = Pd = Cfg;
w = 0;
do {
   if (*Cfg=='*') w++;
   do {
      c = *Cfg++;
      if (c==0) break;
      if (isspace(c)) break;
      *Pd++ = c;
      } while (1);
   *Pd++ = 0;
   if (w) w++;
   while (isspace(*Cfg)) Cfg++;
   } while (w<3);
*Pd = 0;
Cfg++;
while (isspace(*Cfg)) Cfg++;
return Cfg;
}

static char *searchContentType(char *Nft) {
char *P,*E,*C;
int s;
P = Srvcfg.Mtl;
E = CAS_endOfString(Nft,0);
do {
   if (*P=='*') {
      C = P + 2;
      break;
      }
   s = strlen(P);
   if (E-Nft>=s) s = strncasecmp(E-s,P,s) == 0;
      else s = 0;
   C = CAS_endOfString(P,1);
   if (s) break;
   P = CAS_endOfString(C,1);
   } while (*P);
return C;
}

void CAS_sendFileToClient(CAS_srvconn_t *Conn, char *Nft, char *Rhf, int (*valid)(char *)) {
int fh,fs,s;
char *F,*E,*C,*P;
fh = 0;
F = Nft;
if (P=strrchr(F,'/')) F = P + 1;
if (valid) if (valid(Nft)==0)
   fh--;
if (fh==0) {
   C = searchContentType(Nft);
   if (*C!='?') {
      fh = open(Nft,O_RDONLY);
      if (fh>0) {
         fs = lseek(fh,0,SEEK_END);
         lseek(fh,0,SEEK_SET);
         }
      }
   else errno = EACCES;
   }
((T_threadinfo *)Conn)->Po = Conn->Bfo;
if (fh>0) {
   CAS_nPrintf(Conn,Rhf,C,fs,F);
   sendToClient(Conn,NULL,0);
   #ifdef _Secure_application_server
   do {
      fs = read(fh,Conn->Bfi,Srvcfg.lbf);
      if (fs==0) break;
      sendToClient(Conn,Conn->Bfi,fs);
      } while (1);
   #else
   do {
      s = sendfile(((T_threadinfo *)Conn)->sk,fh,NULL,fs);
      fs -= s;
      } while (fs>0);
   close(fh);
   #endif
   }
else CAS_nPrintf(Conn,"%s%s",CAS_Srvinfo.Rh[1],strerror(errno));
}

void CAS_sendContentToClient(CAS_srvconn_t *Conn, char *Nft, char *Rhf, void *Buf, int siz) {
char *C;
C = searchContentType(Nft);
((T_threadinfo *)Conn)->Po = Conn->Bfo;
if (*C!='?') {
   CAS_nPrintf(Conn,Rhf,C,siz,Nft);
   sendToClient(Conn,NULL,0);
   sendToClient(Conn,Buf,siz);
   }
else CAS_nPrintf(Conn,"%%",CAS_Srvinfo.Rh[1],strerror(EACCES));
}

static void abortConnection(CAS_srvconn_t *Conn, char *Ms) {
struct tm Tim;
char *Bo,*Pc;
int r;
Pc = Conn->Pct;
inet_ntop(CAS_Srvinfo.af,Conn->Ipc,Pc,INET6_ADDRSTRLEN);
((T_threadinfo *)Conn)->Po = Conn->Bfo;
localtime_r(&Conn->uts,&Tim);
CAS_nPrintf(Conn,CAS_Srvinfo.Rh[1]);
Bo = ((T_threadinfo *)Conn)->Po;
CAS_nPrintf(Conn,"%d/%02d/%02d %02d:%02d %s %s\n",Tim.tm_year+1900,Tim.tm_mon+1,Tim.tm_mday,Tim.tm_hour,Tim.tm_min,Pc,Ms);
#ifdef _Release_application_server
r = write(Srvcfg.err,Bo,strlen(Bo));
#else
fputs(Bo,stderr);
#endif
}

static void explodeHeaders(void) {
static char Ht[] = "HTTP", Nl[] = "\n\n";
char *P, *S, **Out;
int k;
if (CAS_Srvinfo.Rh==NULL) {
   k = 0;
   P = Srvcfg.Pcfg;
   do {
      if (memcmp(P,Ht,4)!=0) break;
      k++;
      P = strstr(P,Nl);
      while (isspace(*P)) P++;
      } while (1);
   CAS_Srvinfo.Rh = calloc(k+1,sizeof(char *));
   if (CAS_Srvinfo.Rh==NULL) errorMessage("explodeHeaders",errno);
   }
Out = CAS_Srvinfo.Rh;
k = 0;
P = S = Srvcfg.Pcfg;
do {
   while (isspace(*P)) P++;
   if (memcmp(P,Ht,4)!=0) break;
   S = strstr(P,Nl) + 2;
   *S++ = 0;
   Out[k++] = P;
   P = S;
   } while (1);
Out[k] = NULL;
strcpy(Srvcfg.Herr,CAS_Srvinfo.Rh[1]);
strcat(Srvcfg.Herr,"- ");
CAS_Srvinfo.Rh[1] = Srvcfg.Herr;
}

static void closeSocket(T_threadinfo *Thrd) {
int s;
s = Thrd->sk;
Thrd->sk = 0;
#ifdef _Secure_application_server
if (Thrd->cs>0) {
   SSL_shutdown(Thrd->Ss);
   SSL_free(Thrd->Ss);
   }
#else
shutdown(s,SHUT_WR);
#endif
close(s);
Thrd->rq = 0;
}

#ifdef _Release_application_server

static void errorMessage(char *Ms, int er) {
char *Me;
Me = er ? strerror(er) : "";
sprintf(Srvcfg.Buf,"\nInternal error: %s, %s\n",Ms,Me);
fputs(Srvcfg.Buf,stderr);
if (Srvcfg.err>0) er = write(Srvcfg.err,Srvcfg.Buf,strlen(Srvcfg.Buf));
exit(1);
}

static void processSignal(int snl) {
long long t;
char *Me,*P;
struct tm Tim;
int c;
T_threadinfo *Thrd;
if (snl==SIGCONT) return;
Me = (char *)sys_siglist[snl];
if (snl==SIGALRM) {
   return;
   }
else {
   t = pthread_self();
   for (Thrd=Lsthread.Cl; Thrd->xc; Thrd++)
       if (Thrd->id==t) break;
   if (Thrd->xc==0) errorMessage(Me,0);
   }
CAS_nPrintf(&Thrd->Co,Me);
sendToClient(&Thrd->Co,NULL,0);
closeSocket(Thrd);
localtime_r(&Thrd->Co.uts,&Tim);
for (P=Thrd->Pm; *P; ) {
    P = CAS_endOfString(P,1);
    P = CAS_endOfString(P,1);
    }
t = (P - Thrd->Pm) + 4;
P = Thrd->Bf + (Srvcfg.lbf - t);
memmove(P,Thrd->Pm,t);
Thrd->Pm = P;
Me = Thrd->Bf + sprintf(Thrd->Bf,"%d/%02d/%02d %d:%02d %s\n",Tim.tm_year+1900,
                        Tim.tm_mon+1,Tim.tm_mday,Tim.tm_hour,Tim.tm_min,Me);
while (*P) {
      Me += sprintf(Me," %s=",P);
      P = CAS_endOfString(P,1);
      while (c=(unsigned char)*P++) {
            if (c==' ') {
               *Me++ = '+';
               continue;
               }
            if (isalnum(c) || (c=='_')) {
               *Me++ = c;
               continue;
               }
            Me += sprintf(Me,"%2x",c);
            }
      }
*Me++ = '\n';
c = write(Srvcfg.err,Thrd->Bf,Me-Thrd->Bf);
t = Thrd->id;
Thrd->id = Thrd->rq = 0;
if (snl==SIGALRM) { }
   else pthread_exit(NULL);
}

#else

static void errorMessage(char *Ms, int er) {
perror(Ms);
exit(0);
}

static void processSignal(int snl) {
}

#endif

static void nPuts(CAS_srvconn_t *Conn, char *Buf, int len) {
int d;
do {
   d = Conn->Bft - ((T_threadinfo *)Conn)->Po;
   if (d>len) break;
   memcpy(((T_threadinfo *)Conn)->Po,Buf,d);
   ((T_threadinfo *)Conn)->Po += d;
   sendToClient(Conn,NULL,0);
   Buf += d;
   len -= d;
   } while (1);
if (len>0) {
   memcpy(((T_threadinfo *)Conn)->Po,Buf,len);
   ((T_threadinfo *)Conn)->Po += len;
   }
}

static char *widthFormat(char *Fmt, int *v, int *w) {
int n;
char c;
if (*Fmt=='0') (*v)++;
n = 0;
do {
   c = *Fmt++;
   if (isdigit(c)==0) break;
   n = n * 10 + c - '0';
   } while (1);
*w = n;
return Fmt - 1;
}

static void intToAscii(char *Cnv, char f, int n, int v, int w) {
char Fwk[8],*P;
if (w==0) if (n==0) return;
P = Fwk;
*P++ = '%';
if (v==0) *P++ = '0';
if (w>=10) {
   *P++ = w / 10 + '0';
   w %= 10;
   }
P[0] = w + '0';
P[1] = f;
P[2] = 0;
sprintf(Cnv,Fwk,n);
}

static void longToAscii(char *Cnv, char f, long long n, int v, int w) {
char Fwk[8],*P;
if (w==0) if (n==0) return;
P = Fwk;
*P++ = '%';
if (v==0) *P++ = '0';
if (w>=10) {
   *P++ = w / 10 + '0';
   w %= 10;
   }
P[0] = w + '0';
P[1] = P[2] = 'l';
P[3] = tolower(f);
P[4] = 0;
sprintf(Cnv,Fwk,n);
}

static void floatToAscii(char *Cnv, long double e, char f, int w) {
char Fwk[8],*P;
if (isupper(f)) if (e==0) return;
if (w<0) w = 3;
Fwk[0] = '%';
Fwk[1] = '.';
P = Fwk + 2;
if (w>=10) {
   *P++ = w / 10 + '0';
   w %= 10;
   }
P[0] = w + '0';
P[1] = 'L';
P[2] = 'f';
P[3] = 0;
snprintf(Cnv,27,Fwk,e);
if (P=strchr(Cnv,'.')) {
   if (w>0) P += w + 1;
   if (P-27>Cnv) P = CAS_endOfString(Cnv,0);
   if (*P) *P = 0;
   }
}

void CAS_nPrintf(CAS_srvconn_t *Conn, char *Fmt, ... ) {
union { int n; long long l; long double e; char *C; } V;
va_list Ap;
char *Fpv,Cnv[32],f;
int v,w;
va_start(Ap,Fmt);
while (*Fmt) {
      Fpv = Fmt; Fmt = strchr(Fpv,'%');
      if (Fmt==NULL) Fmt = CAS_endOfString(Fpv,0);
      nPuts(Conn,Fpv,Fmt-Fpv);
      if (*Fmt) Fmt++; else break;
      f = *Fmt++;
      if (f=='.') f = *Fmt++;
      v = w = -1;
      if (isdigit(f)) {
         Fmt = widthFormat(Fmt-1,&v,&w);
         f = *Fmt++;
         }
      if (f==0) break;
      if ((f=='%') || (f==' ')) {
         nPuts(Conn,"%",1);
         continue;
         }
      if (f=='c') {
         Cnv[0] = va_arg(Ap,int);
         nPuts(Conn,Cnv,1);
         continue;
         }
      if (f=='s') {
         V.C = va_arg(Ap,char *);
         v = strlen(V.C);
         if (v==0) continue;
         if (w<=0) w = v;
         if (w>v) w = v;
         nPuts(Conn,V.C,w);
         continue;
         }
      memset(Cnv,0,sizeof(Cnv));
      if (strchr("duxDUX",f)) {
         if (w<0) w = 1;
         if (w>27) w = 27;
         if (isupper(f)) {
            V.l = va_arg(Ap,long long);
            longToAscii(Cnv,f,V.l,v,w);
            }
         else {
            V.n = va_arg(Ap,int);
            intToAscii(Cnv,f,V.n,v,w);
            }
         nPuts(Conn,Cnv,strlen(Cnv));
         continue;
         }
      if (strchr("fFeE",f)) {
         if (tolower(f)=='f') V.e = va_arg(Ap,double);
            else V.e = va_arg(Ap,long double);
         floatToAscii(Cnv,V.e,f,w);
         nPuts(Conn,Cnv,strlen(Cnv));
         continue;
         }
      }
va_end(Ap);
v = Conn->Pct - Conn->Bft;
if (((T_threadinfo *)Conn)->mt<v) ((T_threadinfo *)Conn)->mt = v;
Conn->Pct = Conn->Bft + 1;
}

char *CAS_sPrintf(CAS_srvconn_t *Conn, char *Fmt, ... ) {
union { int n; long long l; long double e; char *C; } V;
va_list Ap;
char *Fpv,*Pb,*Pe,Cnv[28],f;
int v,w;
va_start(Ap,Fmt);
Pb = Pe = Conn->Pct;
errno = ENOMEM;
while (f=*Fmt++) {
      if (Pe+3>=Conn->Pet) return NULL;
      if (f!='%') {
         *Pe++ = f;
         continue;
         }
      f = *Fmt++;
      if (f=='.') f = *Fmt++;
      v = w = -1;
      if (isdigit(f)) {
         Fmt = widthFormat(Fmt-1,&v,&w);
         f = *Fmt++;
         }
      if (f==0) break;
      if ((f=='%') || (f==' ')) {
         *Pe++ = '%';
         continue;
         }
      if (f=='c') {
         Cnv[0] = va_arg(Ap,int);
         *Pe++ = Cnv[0];
         continue;
         }
      if (f=='s') {
         V.C = va_arg(Ap,char *);
         v = strlen(V.C);
         if (w<=0) w = v;
         if (w>v) w = v;
         if (Pe+w+1>=Conn->Pet) return NULL;
         memcpy(Pe,V.C,w);
         Pe += w;
         continue;
         }
      memset(Cnv,0,sizeof(Cnv));
      if (strchr("duxDUX",f)) {
         if (w<0) w = 1;
         if (w>27) w = 27;
         if (isupper(f)) {
            V.l = va_arg(Ap,long long);
            longToAscii(Cnv,f,V.l,v,w);
            }
         else {
            V.n = va_arg(Ap,int);
            intToAscii(Cnv,f,V.l,v,w);
            }
         w = strlen(Cnv);
         if (Pe+w+1>=Conn->Pet) return NULL;
         memcpy(Pe,Cnv,w);
         Pe += w;
         continue;
         }
      if (strchr("fFeE",f)) {
         if (tolower(f)=='f') V.e = va_arg(Ap,double);
            else V.e = va_arg(Ap,long double);
         floatToAscii(Cnv,V.e,f,w);
         w = strlen(Cnv);
         if (Pe+w+1>=Conn->Pet) return NULL;
         if (w>0) memcpy(Pe,Cnv,w);
         continue;
         }
      }
va_end(Ap);
*Pe++ = errno = 0;
Conn->Pct = Pe;
return Pb;
}

char *CAS_loadTextFile(char *Nft) {
int F,l;
char *Bf, *P, *R, *T;
F = open(Nft,O_RDONLY);
if (F<0) errorMessage(Nft,errno);
l = lseek(F,0,SEEK_END);
P = Bf = calloc(l+4,1);
if (P==NULL) errorMessage(Nft,errno);
lseek(F,0,SEEK_SET);
if (read(F,P,l)<0) errorMessage(Nft,errno);
close(F);
P = R = Bf;
while (l=*P++) if (l!='\r') *R++ = l;
*R++ = 0; *R++ = 0;
P = strstr(Nft,".htm");
if (P==NULL) P = strstr(Nft,".xml");
if (P) {
   P = R = Bf;
   while (P=strstr(P,"<!-- Break -->")) {
         if (P>Bf) {
            R = P - 1;
            while (*R==' ') R--;
            if (*R=='\n') P = R + 1;
            }
         *P++ = 0;
         R = strchr(P,'>') + 1;
         if (*R=='\n') R++;
         T = P;
         while (*T++=*R++) ;
         *T++ = 0;
         }
   }
return Bf;
}

int CAS_explodeHtm(char *Htmi, void *Htmo, int siz) {
char **Lhtm, *P;
int k;
Lhtm = (char **)Htmo;
siz /= sizeof(char *);
k = 0;
P = Htmi;
do {
   if (k==siz) {
      memset(Htmo,0,siz*sizeof(char *));
      return 0;
      }
   Lhtm[k++] = P;
   P = CAS_endOfString(P,1);
   } while (*P);
return 1;
}

double CAS_getTime(CAS_srvconn_t *Conn) {
struct timeval Tmv;
T_threadinfo *Thrd;
gettimeofday(&Tmv,NULL);
Thrd = (T_threadinfo *)Conn;
if (Conn->uts==0) {
   Conn->uts = Tmv.tv_sec;
   Thrd->us = Tmv.tv_usec;
   return 0;
   }
return ((double)Tmv.tv_usec - Thrd->us) / 1000000.0 + Tmv.tv_sec - Conn->uts;
}

char *CAS_convertString(CAS_srvconn_t *Conn, char *Str, char op) {
char *Pb, *Pe, c;
Pb = Pe = Conn->Pct;
errno = ENOMEM;
if (op=='U') while (c=*Str++) {
   if (Pe+4>=Conn->Pet) return NULL;
   if (isalnum(c) || (c=='_')) {
      *Pe++ = c;
      continue;
      }
   if (c==' ') {
      *Pe++ = '+';
      continue;
      }
   Pe += sprintf(Pe,"%%%02x",c);
   }
if (op=='H') while (c=*Str++) {
   if (Pe+8>=Conn->Pet) return NULL;
   switch (c) {
          case '<':
               Pe += sprintf(Pe,"&lt;");
               break;
          case '>':
               Pe += sprintf(Pe,"&gt;");
                     break;
          case '"':
               Pe += sprintf(Pe,"&quot;");
               break;
          case '&':
               Pe += sprintf(Pe,"&amp;");
               break;
          default:
               *Pe++ = c;
               break;
          }
   }
*Pe++ = errno = 0;
Conn->Pct = Pe;
return Pb;
}

static int checkingPort(int p, int n, char *M) {
time_t ti;
int k,d;
d = socket(CAS_Srvinfo.af,SOCK_STREAM,IPPROTO_TCP);
if (d<0) errorMessage("socket",errno);
inet_pton(CAS_Srvinfo.af,Srvcfg.Buf,&Srvcfg.San);
fprintf(stderr,"Checking port %d, %s\n",p,M);
if (CAS_Srvinfo.af==AF_INET) {
   Srvcfg.Sao.sin_family = CAS_Srvinfo.af;
   Srvcfg.Sao.sin_port = htons(p);
   }
else {
   Srvcfg.San.sin6_family = CAS_Srvinfo.af;
   Srvcfg.San.sin6_port = htons(p);
   }
k = 1;
setsockopt(d,SOL_SOCKET,SO_REUSEADDR,&k,sizeof(k));
k = 0;
ti = time(NULL);
while (bind(d,(struct sockaddr *)&Srvcfg.San,sizeof(Srvcfg.San))<0) {
      if (time(NULL)-ti>Srvcfg.Trcv.tv_sec) k = ETIMEDOUT;
      if (errno==EADDRINUSE) k = errno;
      if (k!=0) errorMessage("bind",k);
      }
if (listen(d,n)<0) errorMessage("listen",errno);
return d;
}

static int initServer(void) {
CAS_srvconn_t *Conn;
char *Ms;
int k;
Srvcfg.Rlim.rlim_cur = Srvcfg.Rlim.rlim_max = Srvcfg.stks * sizeof(int);
setrlimit(RLIMIT_STACK,&Srvcfg.Rlim);
explodeHeaders();
#ifdef _Release_application_server
sprintf(Srvcfg.Buf,"%s.err",Srvcfg.Nprg);
k = open(Srvcfg.Buf,O_APPEND|O_CREAT|O_WRONLY|O_DSYNC,0600);
if (k<0) errorMessage("errLog",errno);
Srvcfg.nls = 1;
#else
k = 0;
#endif
#ifdef _Secure_application_server
Ms = "admin and internet (unsecure) requests";
#else
Ms = "admin and internet requests";
#endif
Srvcfg.Pof[0].fd = checkingPort(Srvcfg.Lpo[0],Lsthread.nc,Ms);
Srvcfg.Pof[0].events = POLLIN;
return k;
}

static char *scanConfig(char *Cfg, char *Fmt, ...) {
union { char **C; char *A; int *N; time_t *T; } Pv;
va_list Prms;
char *Ps,ch;
va_start(Prms,Fmt);
do {
   ch = *Fmt++;
   if (ch==0) break;
   while (isspace(*Cfg)) Cfg++;
   if (*Cfg=='-') break;
   Ps = Cfg;
   while (*Cfg)
         if (isspace(*Cfg)==0) Cfg++;
            else break;
   *Cfg++ = 0;
   if (ch=='s') {
      Pv.C = va_arg(Prms,char **);
      *Pv.C = Ps;
      continue;
      }
   if (ch=='d') {
      if (isdigit(*Ps)==0) break;
      Pv.N = va_arg(Prms,int *);
      *Pv.N = atoi(Ps);
      continue;
      }
   if (ch=='t') {
      if (isdigit(*Ps)==0) break;
      Pv.T = va_arg(Prms,time_t *);
      *Pv.T = atoi(Ps);
      continue;
      }
   if (ch=='a') {
      Pv.A = va_arg(Prms,char *);
      inet_pton(CAS_Srvinfo.af,Ps,Pv.A);
      continue;
      }
   } while (1);
va_end(Prms);
return Cfg;
}

static void *readConfig(void *Npg) {
static char Ecf[] = "readConfig";
T_threadinfo *Thrd;
int n,s;
char *Ps;
if (Npg) {
   Srvcfg.Nprg = Npg;
   if (Ps=strrchr(Srvcfg.Nprg,'/')) Srvcfg.Nprg = Ps + 1;
   sprintf(Srvcfg.Ncfg,"%s.cfg",Srvcfg.Nprg);
   #ifdef _Secure_application_server
   sprintf(Secinf.Nkey,"%s.key",Srvcfg.Nprg);
   #endif
   }
else {
   #ifdef _Secure_application_server
   SSL_CTX_free(Secinf.Ctx);
   #endif
   for (Thrd=Lsthread.Cl; Thrd->xc; Thrd++)
       free(Thrd->Bf);
   free(Srvcfg.Pcfg);
   }
Srvcfg.Pcfg = Ps = CAS_loadTextFile(Srvcfg.Ncfg);
Ps = strstr(Ps,"- Server ");
Ps = strchr(Ps,'\n');
Ps = scanConfig(Ps,"sd",&Srvcfg.Pswd,&n);
Srvcfg.lpw = strlen(Srvcfg.Pswd);
if (n==4) {
   CAS_Srvinfo.af = AF_INET;
   Srvcfg.Psa = &Srvcfg.Sao.sin_addr.s_addr;
   Srvcfg.lsa = 4;
   }
else {
   CAS_Srvinfo.af = AF_INET6;
   Srvcfg.Psa = Srvcfg.San.sin6_addr.s6_addr;
   Srvcfg.lsa = 16;
   }
Ps = scanConfig(Ps,"aa",Srvcfg.Psa,Srvcfg.Lhst);
Ps = scanConfig(Ps,"dd",Srvcfg.Lpo,Srvcfg.Lpo+1);
Ps = scanConfig(Ps,"ddddddtdddd",&n,&Srvcfg.pto,&s,&Srvcfg.sBfi,&Srvcfg.sBfo,&Srvcfg.sBft,&Srvcfg.Trcv.tv_sec,
                &Srvcfg.norp,&CAS_Srvinfo.fs,&CAS_Srvinfo.se,&CAS_Srvinfo.ns);
if (CAS_Srvinfo.fs>0)
   CAS_Srvinfo.fs = (CAS_Srvinfo.fs + 1023) & ~1023;
#ifdef _Secure_application_server
readCertificate();
X509_free(Secinf.Ctf);
RSA_free(Secinf.Rsa);
#endif
if (Lsthread.nc==0) {
   #ifndef _Release_application_server
   n = 1;
   #endif
   Lsthread.nc = n;
   Srvcfg.stks = (s + 1023) & ~1023;
   Lsthread.Cl = calloc(n+1,sizeof(T_threadinfo));
   if (Lsthread.Cl==NULL) errorMessage(Ecf,errno);
   for (s=0,Thrd=Lsthread.Cl; s<n; s++,Thrd++)
       Thrd->xc++;
   }
Srvcfg.sBfi = (Srvcfg.sBfi + 1023) & ~1023;
if (Srvcfg.norp>0) {
   Srvcfg.norp = (Srvcfg.norp + 1023) & ~1023;
   if (Srvcfg.norp>=Srvcfg.sBfi) Srvcfg.sBfi = Srvcfg.norp + 1024;
   }
if (CAS_Srvinfo.ss>0) Srvcfg.sBft += CAS_Srvinfo.ss + 40;
Srvcfg.sBfo = (Srvcfg.sBfo + 1023) & ~1023;
Srvcfg.sBft = (Srvcfg.sBft + 1023) & ~1023;
Srvcfg.lbf = Srvcfg.sBfi + Srvcfg.sBfo + Srvcfg.sBft;
if (Lsthread.nc>0) for (Thrd=Lsthread.Cl; Thrd->xc; Thrd++) {
   Thrd->Bf = calloc(Srvcfg.lbf,1);
   if (Thrd->Bf==NULL) errorMessage(Ecf,errno);
   }
if (CAS_Srvinfo.cnfg) {
   Ps = strstr(Ps,"- User ");
   Ps = strchr(Ps,'\n');
   while (isspace(*Ps)) Ps++;
   CAS_Srvinfo.cnfg(Ps);
   }
return NULL;
}

static void processMessage(char *Cmd) {
time_t ti;
int p,d;
sprintf(Srvcfg.Buf,"%s %s",Cmd,Srvcfg.Pswd);
d = socket(CAS_Srvinfo.af,SOCK_STREAM,IPPROTO_TCP);
if (d<0) errorMessage("",errno);
p = Srvcfg.Lpo[0];
if (CAS_Srvinfo.af==AF_INET) {
   Srvcfg.Sao.sin_family = CAS_Srvinfo.af;
   Srvcfg.Sao.sin_port = htons(p);
   memcpy(&Srvcfg.Sao.sin_addr.s_addr,Srvcfg.Lhst,4);
   }
else {
   Srvcfg.San.sin6_family = CAS_Srvinfo.af;
   Srvcfg.San.sin6_port = htons(p);
   memcpy(Srvcfg.San.sin6_addr.s6_addr,Srvcfg.Lhst,16);
   }
ti = time(NULL);
p = 0;
do {
   if (connect(d,(struct sockaddr *)&Srvcfg.San,sizeof(Srvcfg.San))==0)
      break;
   if (time(NULL)-ti>Srvcfg.Trcv.tv_sec) {
      p = ETIMEDOUT;
      break;
      }
   } while (1);
if (p!=0) errorMessage("connect",p);
send(d,Srvcfg.Buf,strlen(Srvcfg.Buf),0);
setsockopt(d,SOL_SOCKET,SO_RCVTIMEO,&Srvcfg.Trcv,sizeof(Srvcfg.Trcv));
do {
   memset(Srvcfg.Buf,0,sizeof(Srvcfg.Buf));
   recv(d,Srvcfg.Buf,sizeof(Srvcfg.Buf)-1,0);
   if (Srvcfg.Buf[0]==0) break;
   p++;
   fprintf(stderr,"%s",Srvcfg.Buf);
   } while (1);
if (p==0) perror("No response");
close(d);
}

char *CAS_getParamName(CAS_srvconn_t *Conn, char *From) {
char *P;
if (P=From) {
   P = CAS_endOfString(From,1);
   P = CAS_endOfString(P,1);
   }
else P = ((T_threadinfo *)Conn)->Pm;
return *P ? P : NULL;
}

char *CAS_getParamValue(CAS_srvconn_t *Conn, char *Name, char *From) {
char *P,*Q;
if (From) {
   P = From;
   P = CAS_endOfString(P,1);
   }
else P = ((T_threadinfo *)Conn)->Pm;
do {
   Q = CAS_endOfString(P,1);
   if (strcmp(P,Name)==0) return Q;
   P = CAS_endOfString(Q,1);
   } while (*P);
return NULL;
}

char *CAS_getLastParamValue(CAS_srvconn_t *Conn, char *Name) {
char *F,*P;
F = NULL;
do {
   P = CAS_getParamValue(Conn,Name,F);
   if (P==NULL) break;
   F = P;
   } while (1);
return F ? F : CAS_Srvinfo.Nv;
}

char *CAS_getHeaderName(CAS_srvconn_t *Conn, char *From) {
char *P;
if (From) {
   P = CAS_endOfString(From,1);
   P = CAS_endOfString(P,1);
   }
else P = ((T_threadinfo *)Conn)->Hm;
return *P ? P : NULL;
}

char *CAS_getHeaderValue(CAS_srvconn_t *Conn, char *Name) {
char *P,*Q;
P = ((T_threadinfo *)Conn)->Hm;
do {
   Q = CAS_endOfString(P,1);
   if (strcasecmp(P,Name)==0) return Q;
   P = CAS_endOfString(Q,1);
   } while (*P);
return NULL;
}

static struct { char *Eol, *Mna, *Mcl, *Clb, *Mrj, *Mhd, *Ctn, *Zzz, *Clv; } Texts = {
       "\r\n", "%s method not allowed", "%s Missing Content-length",
       "%s Content-length too big (%u)", "%s method rejected",
       "%s Missing end of headers", "%s Content-type not allowed",
       NULL, "Content-length" } ;

static char *parseGetParams(T_threadinfo *Thrd, char *Pm) {
char *Ds,W[3],c;
int v,s;
for (Ds=Pm; c=*Ds; Ds++) if (isspace(c)) break;
if (c) Ds[0] = Ds[1] = 0;
Ds = Thrd->Pm;
s = 0;
do {
   if (*Pm==0) break;
   do {
      c = *Pm++;
      if (c==0) break;
      if (c=='=') break;
      if (c=='&') break;
      if (c=='+') c = ' ';
      if (c=='%') {
         W[0] = W[1] = W[2] = 0;
         if (c=*Pm++) W[0] = c;
         if (c=*Pm++) W[1] = c;
         v = 0;
         sscanf(W,"%x",&v);
         c = s || v > ' ' ? v : '_';
         }
      *Ds++ = c;
      } while (1);
   if (s==0) if (*(Ds-1)==0)
      *Ds++ = '_';
   *Ds++ = 0;
   s = 1 - s;
   } while (1);
*Ds++ = 0;
*Ds++ = 0;
s = Ds - Thrd->Bf;
if (Thrd->mi<s) Thrd->mi = s;
if (Ds>Thrd->Ei) Thrd->Ei = Ds;
return Ds;
}

static char *parseHeaderMessages(T_threadinfo *Thrd, char *Hm) {
int k,c;
char *Ds;
Ds = Thrd->Hm;
while (Hm) {
      while (isspace(*Hm)) Hm++;
      if (*Hm==0) break;
      while (c=*Hm++) {
            if (c!=':') if (isspace(c)==0) {
               *Ds++ = c;
               continue;
               }
            *Ds++ = 0;
            break;
            }
      if (c==0) break;
      while (isspace(*Hm)) Hm++;
      if (*Hm==0) break;
      while (c=*Hm++) {
            if (c=='\r') break;
            if (c=='\n') break;
            *Ds++ = c;
            }
      *Ds++ = 0;
      if (c==0) break;
      }
*Ds++ = 0;
*Ds++ = 0;
k = Ds - Thrd->Bf;
if (Thrd->mi<k) Thrd->mi = k;
if (Ds>Thrd->Ei) Thrd->Ei = Ds;
return Ds;
}

static int isGetMethod(T_threadinfo *Thrd) {
char *Bi,*Hm;
Bi = Thrd->Bf;
if (CAS_Srvinfo.rwrl) CAS_Srvinfo.rwrl(&Thrd->Co);
Bi[1] = Bi[2] = 0;
Bi += 5;
if (Bi[0]!='?') {
   if (Bi[0]>' ') return 404;
   }
else Bi++;
if (Hm=strpbrk(Bi,Texts.Eol)) *Hm++ = 0;
Thrd->Hm = parseGetParams(Thrd,Bi);
if (Hm) parseHeaderMessages(Thrd,Hm);
return 200;
}

static int contentLength(CAS_srvconn_t *Conn, int lM) {
char *Hv;
int l;
l = 0;
if (Hv=CAS_getHeaderValue(Conn,Texts.Clv))
   l = atoi(Hv);
if (l<=0) return -2;
if (l>lM) return -3;
return l;
}

static char *searchBody(char *Bi, int *k) {
char c,d;
*k = 1;
Bi = strpbrk(Bi,Texts.Eol);
if (Bi==NULL) {
   *k = -5;
   return NULL;
   }
c = *Bi;
d = 0;
if (c=='\r') if (Bi[1]=='\n')
   d = '\n';
if (c=='\n') if (Bi[1]=='\r')
   d = '\r';
do {
   if (d) Bi += 2; else Bi++;
   if (Bi[0]==c) {
      if (d) Bi++;
      break;
      }
   Bi = strchr(Bi+1,c);
   if (Bi==NULL) {
      *k = -5;
      return NULL;
      }
   } while (1);
return Bi + 1;
}

static int isLoadMethod(T_threadinfo *Thrd, int l) {
char *Bi,*Pp,*Pr;
int F,c,s,m,w;
if (CAS_Srvinfo.fs==0) return -1;
Bi = Thrd->Bf;
if (Bi[6]!='?') return 404;
Pp = searchBody(Bi,&c);
if (c<0) return c;
s = l - (Pp - Bi);
for (Pr=Pp-1; isspace(*Pr); Pr--) ;
Pr[1] = Pr[2] = 0;
Pr = strpbrk(Bi,Texts.Eol);
Bi[1] = Bi[2] = 0;
Bi += 7;
Thrd->Hm = parseGetParams(Thrd,Bi);
if (Thrd->Pm[0]==0) return 404;
parseHeaderMessages(Thrd,Pr);
c = contentLength(&Thrd->Co,CAS_Srvinfo.fs);
if (c<0) return c;
if (CAS_Srvinfo.post) if (CAS_Srvinfo.post(&Thrd->Co,c,s)==0)
   return -4;
Pr = Thrd->Co.Ufn;
CAS_convertBinaryToName(Pr,3,Thrd-Lsthread.Cl);
F = open(Pr,O_WRONLY|O_CREAT|O_TRUNC,0600);
s = s > 0 ? write(F,Pp,s) : 0;
Pr = Thrd->Co.Bfo;
l = Srvcfg.norp;
m = Thrd->Co.Pet - Pp;
while (s<c) {
      if (l<Srvcfg.norp) {
         close(F);
         if (l<=0) return 0;
         return l > 6 ? -l : -7;
         }
      l = c - s;
      if (l>m) l = m;
      l = recvFromClient(Thrd,Pr,l);
      w = write(F,Pr,l);
      s += l;
      }
close(F);
return 200;
}

static int isPostMethod(T_threadinfo *Thrd, int l) {
char *Bi,*Pp,*Pr;
int c,s,m;
if (Srvcfg.norp==0) return -1;
Bi = Thrd->Bf;
Pp = searchBody(Bi,&c);
if (c<0) return c;
for (Pr=Pp-1; isspace(*Pr); Pr--) ;
Pr[1] = Pr[2] = 0;
Pr = strpbrk(Bi,Texts.Eol);
Bi[1] = Bi[2] = 0;
Bi += 3;
Pr = parseHeaderMessages(Thrd,Pr);
s = strlen(Pp) + 1;
memmove(Pr,Pp,s);
Pr[s+1] = 0;
Thrd->Pm = Pp = Pr;
l = Thrd->Co.Pet - Pp - 4;
m = (Thrd->Co.Bfo - Pp) * 3 - 4;
if (l>m) l = m;
m = strlen(Pp);
c = contentLength(&Thrd->Co,l);
if (c<0) return c;
if (CAS_Srvinfo.post) if (c>m)
   if (CAS_Srvinfo.post(&Thrd->Co,c,m)==0)
      return -4;
if (Pr=CAS_getHeaderValue(&Thrd->Co,"Content-type"))
   if (strcasecmp(Pr,"application/x-www-form-urlencoded")!=0)
      return -6;
s = strlen(Pp);
Pr = Pp;
l = Srvcfg.norp;
while (s<c) {
      if (l<Srvcfg.norp) {
         if (l<=0) return 0;
         return l > 6 ? -l : -7;
         }
      l = c - s;
      l = recvFromClient(Thrd,Pr,l);
      Pr += l;
      s += l;
      }
Pp[s] = Pp[s+1] = 0;
if (Pr) Pr = parseGetParams(Thrd,Pp);
return 200;
}

static int receiveRequest(T_threadinfo *Thrd) {
static char **Perr = (char **)&Texts;
int k,c;
char *Bi,*Me;
int (*PostOrLoad)(T_threadinfo *, int);
CAS_getTime(&Thrd->Co);
Thrd->Co.Bfi = Thrd->Ei = Bi = Thrd->Bf;
memset(Bi,0,Srvcfg.lbf);
Thrd->Co.Bfo = Thrd->Po = Bi + Srvcfg.sBfi;
Thrd->Co.Bft = Thrd->Co.Bfo + Srvcfg.sBfo;
Thrd->Co.Pct = Thrd->Co.Bft + 1;
Thrd->Co.Pet = Thrd->Co.Bft + Srvcfg.sBft;
Thrd->Pm = Thrd->Hm = Bi + 3;
if (memcmp(Thrd->Co.Ipc,Srvcfg.Lhst,sizeof(Srvcfg.Lhst))!=0)
   if (CAS_Srvinfo.acco) if (CAS_Srvinfo.acco(Thrd->Co.Ipc)==0) {
      abortConnection(&Thrd->Co,"Connection refused");
      return 0;
      }
#ifdef _Secure_application_server
if (Thrd->cs>0) {
   k = 1;
   Thrd->Ss = SSL_new(Secinf.Ctx);
   if (Thrd->Ss) {
      SSL_set_fd(Thrd->Ss,Thrd->sk);
      k = SSL_accept(Thrd->Ss);
      if (k<=0) SSL_free(Thrd->Ss);
      }
   else k--;
   if (k<=0) {
      Thrd->cs = 0;
      Me = secureError(Thrd,"Accept");
      abortConnection(&Thrd->Co,Me);
      return 0;
      }
   }
#endif
setsockopt(Thrd->sk,SOL_SOCKET,SO_RCVTIMEO,&Srvcfg.Trcv,sizeof(Srvcfg.Trcv));
k = 1;
setsockopt(Thrd->sk,SOL_TCP,TCP_NODELAY,&k,sizeof(k));
k = recvFromClient(Thrd,Thrd->Bf,Srvcfg.lbf-4);
Me = "Request timeout";
#ifdef _Secure_application_server
if (Bi[0]==0) Me = secureError(Thrd,"Read");
#endif
if (Bi[0]==0) {
   abortConnection(&Thrd->Co,Me);
   return 0;
   }
c = memcmp(Bi,"GET /",5);
#ifdef _Secure_application_server
if (Thrd->cs==0) {
   if (c==0) return redirectToHttps(Thrd);
   return 404;
   }
#endif
if (c==0) return isGetMethod(Thrd);
do {
   if (memcmp(Bi,"POST /",6)==0) {
      PostOrLoad = isPostMethod;
      break;
      }
   if (memcmp(Bi,"LOAD /",6)==0) {
      PostOrLoad = isLoadMethod;
      break;
      }
   return 404;
   } while (0);
k = PostOrLoad(Thrd,k);
if (k>0) return k;
if (k<0) {
   k = -k;
   if (k<=6) {
      Me = Perr[k];
      if (k==3) {
         Bi = CAS_getHeaderValue(&Thrd->Co,Texts.Clv);
         k = atoi(Bi);
         }
      }
   else Me = "%s %d octets read";
   Bi = Thrd->Bf[0] == 'P' ? "POST:" : "LOAD:";
   Me = CAS_sPrintf(&Thrd->Co,Me,Bi,k);
   }
abortConnection(&Thrd->Co,Me);
return 0;
}

static void setSignal(int snl, void (*sHnd)(int), int fl) {
struct sigaction Act;
memset(&Act,0,sizeof(Act));
Act.sa_handler = sHnd;
Act.sa_flags = fl;
sigaction(snl,&Act,NULL);
}

static void processRequest(CAS_srvconn_t *Conn) {
char *Ei;
int k;
Ei = ((T_threadinfo *)Conn)->Ei;
memset(Ei,0,Conn->Pet-Ei);
if (Conn->Bfo>=Ei) {
   k = ((Ei - Conn->Bfi) + 1023) & ~1023;
   Ei = Conn->Bfi + k;
   if (Conn->Bfo>Ei)
      ((T_threadinfo *)Conn)->Po = Conn->Bfo = Ei;
   CAS_nPrintf(Conn,CAS_Srvinfo.Rh[0]);
   CAS_Srvinfo.preq(Conn);
   if (CAS_Srvinfo.ss>0) CAS_updateSession(Conn);
   }
else {
   Ei = CAS_sPrintf(Conn,"Input buffer overflow (%d octets needed)",Ei-Conn->Bfi);
   CAS_nPrintf(Conn,CAS_Srvinfo.Rh[1],Ei);
   }
}

#ifdef _Release_application_server

static T_threadinfo *specialRequest(T_threadinfo *Thrd, char req) {
int k;
for (k=0; Thrd->xc; Thrd++) {
    if (req=='W') if (Thrd->rq=='D') {
       Thrd->rq = 0;
       continue;
       }
    if (Thrd->rq!=req) continue;
    if (req!='S') {
       Thrd->rq = 0;
       if (k>0) return Thrd;
       }
    k++;
    switch (req) {
           case 'Z': Srvcfg.req = 'Z';
                     break;
           case 'C': readConfig(NULL);
                     explodeHeaders();
                     break;
           case 'D': CAS_Srvinfo.data('R');
                     CAS_Srvinfo.data('L');
                     break;
           case 'H': CAS_Srvinfo.html('R');
                     CAS_Srvinfo.html('L');
                     break;
           }
    if (req!='S')
       CAS_nPrintf(&Thrd->Co,"Ok server %s %d (release version) %s\n",Srvcfg.Nprg,getpid(),whichMessage(req));
    if (req=='W') {
       sendToClient(&Thrd->Co,NULL,0);
       recv(Thrd->sk,Thrd->Bf,1020,0);
       if (memcmp(Thrd->Bf,Okdt,7)==0) {
          CAS_Srvinfo.data('R');
          CAS_Srvinfo.data('L');
          }
       }
    pthread_kill(Thrd->td,SIGCONT);
    }
return NULL;
}

static T_threadinfo *threadAvailable(int ca) {
T_threadinfo *Thrd;
int k,r;
do {
   Srvcfg.req = k = 0;
   Thrd = Lsthread.Cl;
   for (; Thrd->xc; Thrd++) {
       if (Thrd->sk==0) {
          if (ca) {
             Srvcfg.req = 0;
             return Thrd;
             }
          continue;
          }
       r = Thrd->rq;
       switch (r) {
              case 0: k |= 1; break;
              case 'S': Srvcfg.req = 'S';
                        k |= 2; break;
              case 'W': k |= 4; break;
              case 'C': k |= 8; break;
              case 'D': k |= 16; break;
              case 'H': k |= 32; break;
              case 'Z': if (ca) {
                           Thrd->rq = 0;
                           pthread_kill(Thrd->td,SIGCONT);
                           }
                        else k |= 0x400;
                        break;
              }
       }
   if (ca) {
      if (k==0) continue;
      }
   else {
      if (k<=1) break;
      }
   if ((k&0x7ffe)==0x400) Srvcfg.req = 'Z';
   if (k%2>0) {
      if (ca || (k>1)) {
         for (r=0,Thrd=Lsthread.Cl; Thrd->xc; Thrd++)
             if (Thrd->sk>0) if (Thrd->rq==0)
                r++;
         if (r>0) {
            Srvcfg.psu++;
            sigwaitinfo(&Srvcfg.Wmsk,NULL);
            Srvcfg.psu--;
            }
         }
      continue;
      }
   if (k & 2) specialRequest(Lsthread.Cl,'S');
   if (k & 4) specialRequest(Lsthread.Cl,'W');
   if (k & 0x400) {
      specialRequest(Lsthread.Cl,'Z');
      Srvcfg.req = 'Z';
      break;
      }
   if (k & 8) specialRequest(Lsthread.Cl,'C');
   if (k & 16) specialRequest(Lsthread.Cl,'D');
   if (k & 32) specialRequest(Lsthread.Cl,'H');
   if (ca>0) continue;
   if (Srvcfg.req!='Z') if (Srvcfg.req!='S') Srvcfg.req = 0;
   break;
   } while (1);
return NULL;
}

static int performAdminRequest(CAS_srvconn_t *Conn) {
char Ip[INET6_ADDRSTRLEN];
T_threadinfo *Thrd;
int s,k;
k = checkAdminRequest(Conn);
if (k==404) return k;
Thrd = (T_threadinfo *)Conn;
switch (k) {
       case 'S':
            CAS_nPrintf(Conn,"Ok server %s pid %d --show\nThread Socket IP address\n",Srvcfg.Nprg,getpid());
            for (s=0,Thrd=Lsthread.Cl; Thrd->xc; s++,Thrd++)
                if (Thrd->td) if (Thrd->sk) {
                   inet_ntop(CAS_Srvinfo.af,&Thrd->Co.Ipc,Ip,sizeof(Ip));
                   CAS_nPrintf(Conn,"%6d %6d  %s\n",s+1,Thrd->sk,Ip);
                   }
            for (s=0,Thrd=Lsthread.Cl; Thrd->xc; Thrd++)
                if (Thrd->mi>s) s = Thrd->mi;
            CAS_nPrintf(Conn,"Buffer for input strings: %d octets\n",s+4);
            for (s=0,Thrd=Lsthread.Cl; Thrd->xc; Thrd++)
                if (Thrd->mt>s) s = Thrd->mt;
            CAS_nPrintf(Conn,"Buffer for temporary strings: %d octets\n",s+4);
            CAS_nPrintf(Conn,"Maximum stack size: %d octets\n",(s+4)*sizeof(int));
            k = 'S';
            break;
       case 'E':
            deleteExpiredSession(Conn);
            CAS_nPrintf(Conn,CAS_Srvinfo.Rh[0]);
            break;
       default:
            Thrd->rq = k;
            pthread_kill(Srvcfg.tid,SIGCONT);
            sigwaitinfo(&Srvcfg.Wmsk,NULL);
            Thrd->rq = 0;
            break;
       }
return k;
}

static void *userRequest(T_threadinfo *Thrd) {
int hk;
do {
   if (Srvcfg.req=='Z') break;
   if (Thrd->sk==0) {
      sigwaitinfo(&Srvcfg.Wmsk,NULL);
      continue;
      }
   hk = receiveRequest(Thrd);
   if (hk==200) {
      #ifdef _Secure_application_server
      Thrd->Co.Bfi[1] = 's';
      #endif
      processRequest(&Thrd->Co);
      }
   if (hk==404) hk = performAdminRequest(&Thrd->Co);
   if (hk==404) CAS_nPrintf(&Thrd->Co,"%s Not found\n",CAS_Srvinfo.Rh[1]);
   if (Thrd->rq=='S') CAS_multithreading(&Thrd->Co,'R');
   sendToClient(&Thrd->Co,NULL,0);
   closeSocket(Thrd);
   if (Srvcfg.psu) pthread_kill(Srvcfg.tid,SIGCONT);
   } while (1);
Thrd->id = Thrd->rq = 0;
return NULL;
}

static void serverCycle(void) {
T_threadinfo *Thrd;
struct pollfd *Ppo;
int *Sb, k, n, s;
char *Ms;
pthread_attr_setdetachstate(&Srvcfg.Attr,PTHREAD_CREATE_DETACHED);
s = Srvcfg.stks;
if (s<PTHREAD_STACK_MIN) s = PTHREAD_STACK_MIN;
pthread_attr_setstacksize(&Srvcfg.Attr,s);
setSignal(SIGSEGV,processSignal,SA_ONSTACK);
setSignal(SIGFPE,processSignal,0);
setSignal(SIGCONT,processSignal,0);
setSignal(SIGPIPE,SIG_IGN,0);
sigfillset(&Srvcfg.Pmsk);
sigdelset(&Srvcfg.Pmsk,SIGALRM);
sigdelset(&Srvcfg.Pmsk,SIGQUIT);
sigdelset(&Srvcfg.Pmsk,SIGTSTP);
sigfillset(&Srvcfg.Wmsk);
sigdelset(&Srvcfg.Wmsk,SIGALRM);
sigdelset(&Srvcfg.Wmsk,SIGCONT);
sigprocmask(SIG_SETMASK,NULL,&Srvcfg.Pmsk);
Srvcfg.err = initServer();
Ms = "";
#ifdef _Secure_application_server
Ppo = Srvcfg.Pof + 1;
Ppo->fd = checkingPort(Srvcfg.Lpo[1],Lsthread.nc,"only internet (secure) requests");
Ppo->events = POLLIN;
Srvcfg.nls++;
Ms = " and secure";
#endif
fprintf(stderr,"Server active, IPv%d release%s version\n",CAS_Srvinfo.af==AF_INET?4:6,Ms);
do {
   Srvcfg.Pof[0].revents = Srvcfg.Pof[1].revents = n = 0;
   if (ppoll(Srvcfg.Pof,Srvcfg.nls,NULL,&Srvcfg.Wmsk)>0)
      for (k=0,Ppo=Srvcfg.Pof; k<Srvcfg.nls; k++,Ppo++) {
          s = Ppo->revents & POLLIN;
          if (s==0) continue;
          s = sizeof(Srvcfg.San);
          s = accept(Ppo->fd,(struct sockaddr *)&Srvcfg.San,&s);
          if (s<0) continue;
          n++;
          Thrd = threadAvailable(1);
          memset(&Thrd->Co,0,sizeof(CAS_srvconn_t));
          memcpy(Thrd->Co.Ipc,Srvcfg.Psa,Srvcfg.lsa);
          Thrd->sk = s;
          Thrd->cs = k;
          if (Thrd->id==0) pthread_create(&Thrd->td,NULL,(void * (*)(void *))userRequest,Thrd);
             else pthread_kill(Thrd->td,SIGCONT);
          }
   if (n==0) threadAvailable(0);
   } while (Srvcfg.req!='Z');
}

#else

static void *serverCycle(void *Arg) {
T_threadinfo *Thrd;
int k,l,s;
initServer();
fprintf(stderr,"Server active, IPv%d debug version\n",CAS_Srvinfo.af==AF_INET?4:6);
Thrd = Lsthread.Cl;
do {
   k = sizeof(Srvcfg.San);
   k = accept(Srvcfg.Pof[0].fd,(struct sockaddr *)&Srvcfg.San,&k);
   if (k<0) continue;
   memset(Thrd,0,sizeof(CAS_srvconn_t));
   memcpy(Thrd->Co.Ipc,Srvcfg.Psa,Srvcfg.lsa);
   Thrd->sk = k;
   k = receiveRequest(Thrd);
   if (k==200) processRequest(&Thrd->Co);
   else
   if (k==404) {
      k = checkAdminRequest(&Thrd->Co);
      if (k<='Z') {
         switch (k) {
                case 'C': readConfig(NULL);
                          explodeHeaders();
                          break;
                case 'D': CAS_Srvinfo.data('R');
                          CAS_Srvinfo.data('L');
                          break;
                case 'H': CAS_Srvinfo.html('R');
                          CAS_Srvinfo.html('L');
                          break;
                case 'S': CAS_nPrintf(&Thrd->Co,"Buffer for input strings: %d octets\n",Thrd->mi+4);
                          CAS_nPrintf(&Thrd->Co,"Buffer for temporary strings: %d octets\n",Thrd->mt+4);
                          if (Srvcfg.stkT) {
                             for (l=0; l<Srvcfg.stks; l++)
                                 if (Srvcfg.Wstk[l]) {
                                    s = Srvcfg.stks - l;
                                    break;
                                    }
                             }
                          else {
                             for (l=Srvcfg.stks-1,s=0; l>=0; l--)
                                 if (Srvcfg.Wstk[l]) {
                                    s = l;
                                    break;
                                    }
                               }
                          CAS_nPrintf(&Thrd->Co,"Maximum stack size: %d octets\n",s*sizeof(int));
                          break;
                case 'E': deleteExpiredSession(&Thrd->Co);
                          break;
                }
         CAS_nPrintf(&Thrd->Co,"Ok server %s pid %d (debug version) %s\n",Srvcfg.Nprg,getpid(),whichMessage(k));
         }
      if (k=='W') {
         sendToClient(&Thrd->Co,NULL,0);
         recv(Thrd->sk,Thrd->Bf,1020,0);
         if (memcmp(Thrd->Bf,Okdt,7)==0) {
            CAS_Srvinfo.data('R');
            CAS_Srvinfo.data('L');
            }
         }
      if (k==404) CAS_nPrintf(&Thrd->Co,"%s Not found\n",CAS_Srvinfo.Rh[1]);
      }
   sendToClient(&Thrd->Co,NULL,0);
   closeSocket(Thrd);
   } while (k!='Z');
return NULL;
}

#endif

void CAS_multithreading(CAS_srvconn_t *Conn, char opt) {
#ifdef _Release_application_server
static struct timespec Tmsp = { 0, 0 } ;
T_threadinfo *Thrd;
Thrd = (T_threadinfo *)Conn;
switch (opt) {
       case 'R': if (Thrd->rq!='S') return;
                 break;
       case 'S': if (Thrd->rq) return;
                 break;
       default: return;
       }
Thrd->rq = opt;
pthread_kill(Srvcfg.tid,SIGCONT);
if (opt=='S') sigwaitinfo(&Srvcfg.Wmsk,NULL);
#endif
}

static void dummyLoadFree(char op) { }

int main(int agc, char **Agv) {
stack_t Ss;
int s;
CAS_Srvinfo.Nv = "";
CAS_Srvinfo.data = CAS_Srvinfo.html = dummyLoadFree;
CAS_registerUserSettings();
if (CAS_Srvinfo.preq==NULL) {
   fputs("Process request (CAS_Srvinfo.prq) not defined\n",stderr);
   exit(1);
   }
Srvcfg.tid = pthread_self();
#ifdef _Secure_application_server
OpenSSL_add_all_algorithms();
SSL_load_error_strings();
ERR_load_BIO_strings();
Secinf.Mtd = (SSL_METHOD *)TLS_server_method();
#endif
readConfig(Agv[0]);
s = 6;
if (agc==2) for (s=0; Mssg[s]; s++)
   if (strcmp(Agv[1],Mssg[s])==0) break;
if (Mssg[s]==NULL) {
   fputs("The argument of command line must be:\n",stderr);
   fprintf(stderr,"%s\tStart server\n",Mssg[0]);
   fprintf(stderr,"%s\tStop server\n",Mssg[1]);
   fprintf(stderr,"%s\tReload config\n",Mssg[2]);
   fprintf(stderr,"%s\tReload data\n",Mssg[3]);
   fprintf(stderr,"%s\tReload html\n",Mssg[4]);
   fprintf(stderr,"%s\tShow info\n",Mssg[5]);
   return 1;
   }
if (s==0) {
   if (CAS_Srvinfo.ss>0) {
      sprintf(Srvcfg.Buf,"%s.ssn",Srvcfg.Nprg);
      CAS_initSessionSupport(Srvcfg.Buf);
      }
   CAS_Srvinfo.data('L');
   CAS_Srvinfo.html('L');
   setSignal(SIGALRM,processSignal,0);
   pthread_attr_init(&Srvcfg.Attr);
   #ifdef _Release_application_server
   s = MINSIGSTKSZ;
   #ifdef _Secure_application_server
   s += 4096;
   Srvcfg.stks += 4096;
   #endif
   Srvcfg.Wstk = malloc(s);
   Ss.ss_sp = Srvcfg.Wstk;
   Ss.ss_size = s;
   sigaltstack(&Ss,NULL);
   serverCycle();
   #else
   Srvcfg.stkT++; /* drop this line if stack grows upward */
   s = Srvcfg.stks;
   if (s<PTHREAD_STACK_MIN) s = PTHREAD_STACK_MIN;
   Srvcfg.Wstk = calloc(s,1);
   Srvcfg.stks /= sizeof(int);
   pthread_attr_setstack(&Srvcfg.Attr,Srvcfg.Wstk,s);
   pthread_create(&Srvcfg.tid,&Srvcfg.Attr,serverCycle,NULL);
   pthread_join(Srvcfg.tid,NULL);
   #endif
   }
else processMessage(Mssg[s]);
return 0;
}
