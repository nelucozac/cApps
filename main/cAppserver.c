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
#endif

typedef struct {
        CAS_srvconn_t Co;
        #ifdef _Secure_application_server
        SSL *Ss;
        #endif
        int *Sb, pd, mt, mi, sk;
        char *Bf, *Pm, *Hm, *Po, *Ei;
        char rq;
        signed char cs;
        time_t us;
        } T_cloninfo;

CAS_srvinfo_t CAS_Srvinfo;

static char *Cmds[] = { "--start", "--stop", "--cnfg", "--data", "--html", "--show", NULL, "--wait", "--essn" } ;

static struct {
       int stks, sBfi, sBfo, sBft, stkT;
       unsigned char Lhst[16];
       void *Psa;
       int lsa, norp, lbf, lpw;
       int Lpo[2];
       char *Pswd, Ncfg[4096], Herr[256], *Mtl;
       struct itimerval Tpro, Trst;
       struct timeval Trcv;
       } Srvcfg;

static struct {
       struct rlimit Rlim;
       union { struct sockaddr_in Sao; struct sockaddr_in6 San; } ;
       struct pollfd Pof[2];
       sigset_t mask, omsk;
       char *Cfg, *Npg, Buf[4096];
       int pid, err, nls;
       char req;
       } Othinf;

static struct {
       T_cloninfo *Cl;
       int nc;
       } Lstclon;

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

static char *secureError(T_cloninfo *Clon, char *Op) {
char *Er;
int k,l;
Er = Clon->Co.Pct;
l = 0;
do {
   k = ERR_get_error();
   if (k==0) break;
   if (l++>0) continue;
   Clon->Co.Pct = Er + sprintf(Er,"%s - %s",Op,ERR_reason_error_string(k)) + 1;
   } while (1);
return Er;
}

static void errorCertificate(char *Me) {
T_cloninfo *Clon;
fprintf(stderr,"%s - %s\n",Me,ERR_reason_error_string(ERR_get_error()));
if (Lstclon.Cl) {
   for (Clon=Lstclon.Cl; Clon->Sb; Clon++)
       if (Clon->pd>0) kill(Clon->pd,SIGKILL);
   }
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

static int redirectToHttps(T_cloninfo *Clon) {
char *Bi,*Bf,*Pa,c;
int l,p;
if (CAS_Srvinfo.Rh[2]==NULL) return 404;
Bi = Clon->Bf + 4;
do {
   c = *++Bi;
   if (c==0) return 404;
   if (isspace(c)) break;
   } while (1);
if (Bi-Clon->Bf==5) Bi--;
*Bi++ = 0;
Bf = Clon->Bf + 4;
l = strlen(Bf) + 1;
Pa = Clon->Bf + Srvcfg.sBfo - l;
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
   Bf = Clon->Bf + 4;
   break;
   } while (1);
Bf = Clon->Bf;
l = strlen(Bi);
memmove(Bf,Bi,l);
p = Srvcfg.Lpo[1];
if (p!=443) {
   sprintf(Bf+l,":%d",p);
   l = strlen(Bf);
   }
Pa -= l;
memcpy(Pa,Bf,l);
CAS_nPrintf(&Clon->Co,CAS_Srvinfo.Rh[2],Pa);
return 301;
}

#endif

void CAS_resetOutputBuffer(CAS_srvconn_t *Conn) {
((T_cloninfo *)Conn)->Po = Conn->Bfo;
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

static char *whichCommand(char c) {
static char *Scmd = "-ZCDHS-W";
return Cmds[strchr(Scmd,c)-Scmd];
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
if (memcmp(Bf,Cmds[2],6)==0) return 'C';
if (memcmp(Bf,Cmds[3],6)==0) return 'D';
if (memcmp(Bf,Cmds[4],6)==0) return 'H';
if (memcmp(Bf,Cmds[5],6)==0) return 'S';
if (memcmp(Bf,Cmds[7],6)==0) return 'W';
if (memcmp(Bf,Cmds[8],6)==0) return 'E';
if (memcmp(Bf,Cmds[1],6)==0) return 'Z';
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

static int recvFromClient(T_cloninfo *Clon, void *Buf, int len) {
#ifdef _Secure_application_server
if (Clon->cs>0)
   return SSL_read(Clon->Ss,Buf,len);
#endif
return recv(Clon->sk,Buf,len,0);
}

static void sendToClient(CAS_srvconn_t *Conn, char *Bf, int ls) {
T_cloninfo *Clon;
int s;
Clon = (T_cloninfo *)Conn;
if (Bf==NULL) {
   Bf = Conn->Bfo;
   ls = Clon->Po - Bf;
   }
if (ls>0) {
   do {
      #ifdef _Secure_application_server
      if (Clon->cs>0) {
         s = SSL_write(Clon->Ss,Bf,ls);
         if (s<0) secureError(Clon,"");
         }
      else
      #endif
      s = send(Clon->sk,Bf,ls,0);
      if (s==ls) break;
      if (s<=0) break;
      Bf += s;
      ls -= s;
      } while (1);
   memset(Conn->Bfo,0,Conn->Bft-Conn->Bfo);
   Clon->Po = Conn->Bfo;
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
((T_cloninfo *)Conn)->Po = Conn->Bfo;
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
      s = sendfile(((T_cloninfo *)Conn)->sk,fh,NULL,fs);
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
((T_cloninfo *)Conn)->Po = Conn->Bfo;
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
((T_cloninfo *)Conn)->Po = Conn->Bfo;
localtime_r(&Conn->uts,&Tim);
CAS_nPrintf(Conn,CAS_Srvinfo.Rh[1]);
Bo = ((T_cloninfo *)Conn)->Po;
CAS_nPrintf(Conn,"%d/%02d/%02d %02d:%02d %s %s\n",Tim.tm_year+1900,Tim.tm_mon+1,Tim.tm_mday,Tim.tm_hour,Tim.tm_min,Pc,Ms);
#ifdef _Release_application_server
r = write(Othinf.err,Bo,strlen(Bo));
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
   P = Othinf.Cfg;
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
P = S = Othinf.Cfg;
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

static void closeSocket(T_cloninfo *Clon) {
#ifdef _Secure_application_server
if (Clon->cs>0) {
   SSL_shutdown(Clon->Ss);
   SSL_free(Clon->Ss);
   }
#else
shutdown(Clon->sk,SHUT_WR);
#endif
close(Clon->sk);
Clon->sk = Clon->rq = 0;
}

#ifdef _Release_application_server

static void errorMessage(char *Ms, int er) {
T_cloninfo *Clon;
char *Me;
Me = er ? strerror(er) : "";
sprintf(Othinf.Buf,"\nInternal error: %s, %s\n",Ms,Me);
fputs(Othinf.Buf,stderr);
if (Othinf.err>0) er = write(Othinf.err,Othinf.Buf,strlen(Othinf.Buf));
if (Lstclon.Cl) {
   for (Clon=Lstclon.Cl; Clon->Sb; Clon++) {
       if (Clon->pd>0) kill(Clon->pd,SIGKILL);
       }
   }
exit(1);
}

static void processSignal(int snl) {
int c;
char *Me,*P;
struct tm Tim;
T_cloninfo *Clon;
if (snl==SIGCONT) return;
if (snl==SIGCHLD) {
   while (waitpid(-1,NULL,__WALL|WNOHANG)>0) ;
   return;
   }
c = getpid();
for (Clon=Lstclon.Cl; Clon->Sb; Clon++)
    if (Clon->pd==c) break;
if (Clon->Sb==NULL) exit(1);
if (snl==SIGALRM) if (Clon->Co.tmo==0) {
   Clon->Co.tmo++;
   return;
   }
Me = (char *)sys_siglist[snl];
CAS_nPrintf(&Clon->Co,Me);
sendToClient(&Clon->Co,NULL,0);
closeSocket(Clon);
localtime_r(&Clon->Co.uts,&Tim);
for (P=Clon->Pm; *P; ) {
    P = CAS_endOfString(P,1);
    P = CAS_endOfString(P,1);
    }
c = (P - Clon->Pm) + 4;
P = Clon->Bf + Srvcfg.lbf - c;
memmove(P,Clon->Pm,c);
Clon->Pm = P;
Me = Clon->Bf + sprintf(Clon->Bf,"%d/%02d/%02d %d:%02d %s\n",Tim.tm_year+1900,
                        Tim.tm_mon+1,Tim.tm_mday,Tim.tm_hour,Tim.tm_min,Me);
while (*P) {
      Me += sprintf(Me," %s=",P);
      P = CAS_endOfString(P,1);
      while (c=*P++) {
            if (c==' ') {
               *Me++ = '+';
               continue;
               }
            if (isalnum(c) || (c=='_')) {
               *Me++ = c;
               continue;
               }
            Me += sprintf(Me,"%2x",(unsigned)c);
            }
      *P++;
      }
*Me++ = '\n';
c = write(Othinf.err,Clon->Bf,Me-Clon->Bf);
printf("e %d s %s\n",errno,strerror(errno));
#ifdef _Secure_application_server
if (Secinf.Ctx) {
   SSL_CTX_free(Secinf.Ctx);
   Secinf.Ctx = NULL;
   }
#endif
Clon->pd = Clon->rq = Clon->sk = 0;
exit(1);
}

#else

static void errorMessage(char *Ms, int er) {
perror(Ms);
exit(0);
}

static void processSignal(int snl) {
if (snl==SIGCHLD)
   while (waitpid(-1,NULL,__WALL|WNOHANG)>0) ;
if (snl==SIGALRM) Lstclon.Cl[0].Co.tmo = 1;
}

#endif

static void nPuts(CAS_srvconn_t *Conn, char *Buf, int len) {
int d;
do {
   d = Conn->Bft - ((T_cloninfo *)Conn)->Po;
   if (d>len) break;
   memcpy(((T_cloninfo *)Conn)->Po,Buf,d);
   ((T_cloninfo *)Conn)->Po += d;
   sendToClient(Conn,NULL,0);
   Buf += d;
   len -= d;
   } while (1);
if (len>0) {
   memcpy(((T_cloninfo *)Conn)->Po,Buf,len);
   ((T_cloninfo *)Conn)->Po += len;
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
if (((T_cloninfo *)Conn)->mt<v) ((T_cloninfo *)Conn)->mt = v;
Conn->Pct = Conn->Bft + 1;
}

char *CAS_sPrintf(CAS_srvconn_t *Conn, char *Fmt, ... ) {
union { int n; long long l; long double e; char *C; } V;
va_list Ap;
char *Fpv,*Pb,*Pe,Cnv[28],f;
int v,w;
va_start(Ap,Fmt);
Pb = Pe = Conn->Pct;
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
*Pe++ = 0;
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
T_cloninfo *Clon;
gettimeofday(&Tmv,NULL);
Clon = (T_cloninfo *)Conn;
if (Conn->uts==0) {
   Conn->uts = Tmv.tv_sec;
   Clon->us = Tmv.tv_usec;
   return 0;
   }
return ((double)Tmv.tv_usec - Clon->us) / 1000000.0 + Tmv.tv_sec - Conn->uts;
}

char *CAS_convertString(CAS_srvconn_t *Conn, char *Str, char op) {
char *Pb, *Pe, c;
Pb = Pe = Conn->Pct;
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
*Pe++ = 0;
Conn->Pct = Pe;
return Pb;
}

static int checkingPort(int p, int n, char *M) {
time_t ti;
int k,d;
d = socket(CAS_Srvinfo.af,SOCK_STREAM,IPPROTO_TCP);
if (d<0) errorMessage("socket",errno);
inet_pton(CAS_Srvinfo.af,Othinf.Buf,&Othinf.San);
fprintf(stderr,"Checking port %d, %s\n",p,M);
if (CAS_Srvinfo.af==AF_INET) {
   Othinf.Sao.sin_family = CAS_Srvinfo.af;
   Othinf.Sao.sin_port = htons(p);
   }
else {
   Othinf.San.sin6_family = CAS_Srvinfo.af;
   Othinf.San.sin6_port = htons(p);
   }
k = 1;
setsockopt(d,SOL_SOCKET,SO_REUSEADDR,&k,sizeof(k));
k = 0;
ti = time(NULL);
while (bind(d,(struct sockaddr *)&Othinf.San,sizeof(Othinf.San))<0) {
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
Othinf.Rlim.rlim_cur = Othinf.Rlim.rlim_max = Srvcfg.stks * sizeof(int);
setrlimit(RLIMIT_STACK,&Othinf.Rlim);
explodeHeaders();
#ifdef _Release_application_server
sprintf(Othinf.Buf,"%s.err",Othinf.Npg);
k = open(Othinf.Buf,O_APPEND|O_CREAT|O_WRONLY|O_DSYNC,0600);
if (k<0) errorMessage("errLog",errno);
Othinf.nls = 1;
#else
k = 0;
#endif
#ifdef _Secure_application_server
Ms = "admin and internet (unsecure) requests";
#else
Ms = "admin and internet requests";
#endif
Othinf.Pof[0].fd = checkingPort(Srvcfg.Lpo[0],Lstclon.nc,Ms);
Othinf.Pof[0].events = POLLIN;
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

static void readConfig(char *Npg) {
static char Ecf[] = "readConfig";
T_cloninfo *Clon;
int n,s;
char *Ps;
if (Npg) {
   Othinf.Npg = Npg;
   if (Ps=strrchr(Othinf.Npg,'/')) Othinf.Npg = Ps + 1;
   sprintf(Srvcfg.Ncfg,"%s.cfg",Othinf.Npg);
   #ifdef _Secure_application_server
   sprintf(Secinf.Nkey,"%s.key",Othinf.Npg);
   #endif
   }
else {
   #ifdef _Secure_application_server
   SSL_CTX_free(Secinf.Ctx);
   #endif
   for (Clon=Lstclon.Cl; Clon->Sb; Clon++)
       free(Clon->Bf);
   free(Othinf.Cfg);
   }
Othinf.Cfg = Ps = CAS_loadTextFile(Srvcfg.Ncfg);
Ps = strstr(Ps,"- Server ");
Ps = strchr(Ps,'\n');
Ps = scanConfig(Ps,"sd",&Srvcfg.Pswd,&n);
Srvcfg.lpw = strlen(Srvcfg.Pswd);
if (n==4) {
   CAS_Srvinfo.af = AF_INET;
   Srvcfg.Psa = &Othinf.Sao.sin_addr.s_addr;
   Srvcfg.lsa = 4;
   }
else {
   CAS_Srvinfo.af = AF_INET6;
   Srvcfg.Psa = Othinf.San.sin6_addr.s6_addr;
   Srvcfg.lsa = 16;
   }
Ps = scanConfig(Ps,"aa",Srvcfg.Psa,Srvcfg.Lhst);
Ps = scanConfig(Ps,"dd",Srvcfg.Lpo,Srvcfg.Lpo+1);
Ps = scanConfig(Ps,"dtddddtdddd",&n,&Srvcfg.Tpro.it_value.tv_sec,&s,&Srvcfg.sBfi,&Srvcfg.sBfo,&Srvcfg.sBft,
                &Srvcfg.Trcv.tv_sec,&Srvcfg.norp,&CAS_Srvinfo.fs,&CAS_Srvinfo.se,&CAS_Srvinfo.ns);
if (CAS_Srvinfo.fs>0)
   CAS_Srvinfo.fs = (CAS_Srvinfo.fs + 1023) & ~1023;
Srvcfg.Tpro.it_interval.tv_sec = 1;
#ifdef _Secure_application_server
readCertificate();
X509_free(Secinf.Ctf);
RSA_free(Secinf.Rsa);
#endif
if (Lstclon.nc==0) {
   #ifndef _Release_application_server
   n = 1;
   #endif
   Lstclon.nc = n;
   Srvcfg.stks = ((s + 1023) & ~1023) / sizeof(int);
   Lstclon.Cl = calloc(n+1,sizeof(T_cloninfo));
   if (Lstclon.Cl==NULL) errorMessage(Ecf,errno);
   for (s=0,Clon=Lstclon.Cl; s<n; s++,Clon++) {
       Clon->Sb = calloc(Srvcfg.stks,sizeof(int));
       if (Clon->Sb==NULL) errorMessage(Ecf,errno);
       }
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
if (Lstclon.nc>0) for (Clon=Lstclon.Cl; Clon->Sb; Clon++) {
   Clon->Bf = calloc(Srvcfg.lbf,1);
   if (Clon->Bf==NULL) errorMessage(Ecf,errno);
   }
if (CAS_Srvinfo.cnfg) {
   Ps = strstr(Ps,"- User ");
   Ps = strchr(Ps,'\n');
   while (isspace(*Ps)) Ps++;
   CAS_Srvinfo.cnfg(Ps);
   }
if (CAS_Srvinfo.se>0) {
   s = Srvcfg.Tpro.it_value.tv_sec * 2 + 1;
   if (CAS_Srvinfo.se<s) CAS_Srvinfo.se = s;
   }
}

static void processCommand(char *Cmd) {
time_t ti;
int p,d;
sprintf(Othinf.Buf,"%s %s",Cmd,Srvcfg.Pswd);
d = socket(CAS_Srvinfo.af,SOCK_STREAM,IPPROTO_TCP);
if (d<0) errorMessage("",errno);
p = Srvcfg.Lpo[0];
if (CAS_Srvinfo.af==AF_INET) {
   Othinf.Sao.sin_family = CAS_Srvinfo.af;
   Othinf.Sao.sin_port = htons(p);
   memcpy(&Othinf.Sao.sin_addr.s_addr,Srvcfg.Lhst,4);
   }
else {
   Othinf.San.sin6_family = CAS_Srvinfo.af;
   Othinf.San.sin6_port = htons(p);
   memcpy(Othinf.San.sin6_addr.s6_addr,Srvcfg.Lhst,16);
   }
ti = time(NULL);
p = 0;
while (connect(d,(struct sockaddr *)&Othinf.San,sizeof(Othinf.San))<0) {
      if (time(NULL)-ti>Srvcfg.Trcv.tv_sec) p = ETIMEDOUT;
      if (errno==ECONNREFUSED) p = errno;
      if (p!=0) errorMessage("connect",p);
      sleep(1);
      }
send(d,Othinf.Buf,strlen(Othinf.Buf),0);
Srvcfg.Trcv.tv_sec += Srvcfg.Tpro.it_value.tv_sec;
setsockopt(d,SOL_SOCKET,SO_RCVTIMEO,&Srvcfg.Trcv,sizeof(Srvcfg.Trcv));
do {
   memset(Othinf.Buf,0,sizeof(Othinf.Buf));
   recv(d,Othinf.Buf,sizeof(Othinf.Buf)-1,0);
   if (Othinf.Buf[0]==0) break;
   p++;
   fprintf(stderr,"%s",Othinf.Buf);
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
else P = ((T_cloninfo *)Conn)->Pm;
return *P ? P : NULL;
}

char *CAS_getParamValue(CAS_srvconn_t *Conn, char *Name, char *From) {
char *P,*Q;
if (From) {
   P = From;
   P = CAS_endOfString(P,1);
   }
else P = ((T_cloninfo *)Conn)->Pm;
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
else P = ((T_cloninfo *)Conn)->Hm;
return *P ? P : NULL;
}

char *CAS_getHeaderValue(CAS_srvconn_t *Conn, char *Name) {
char *P,*Q;
P = ((T_cloninfo *)Conn)->Hm;
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

static char *parseGetParams(T_cloninfo *Clon, char *Pm) {
char *Ds,W[3],c;
int v,s;
for (Ds=Pm; c=*Ds; Ds++) if (isspace(c)) break;
if (c) Ds[0] = Ds[1] = 0;
Ds = Clon->Pm;
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
s = Ds - Clon->Bf;
if (Clon->mi<s) Clon->mi = s;
if (Ds>Clon->Ei) Clon->Ei = Ds;
return Ds;
}

static char *parseHeaderMessages(T_cloninfo *Clon, char *Hm) {
int k,c;
char *Ds;
Ds = Clon->Hm;
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
k = Ds - Clon->Bf;
if (Clon->mi<k) Clon->mi = k;
if (Ds>Clon->Ei) Clon->Ei = Ds;
return Ds;
}

static int isGetMethod(T_cloninfo *Clon) {
char *Bi,*Hm;
Bi = Clon->Bf;
if (CAS_Srvinfo.rwrl) CAS_Srvinfo.rwrl(&Clon->Co);
Bi[1] = Bi[2] = 0;
Bi += 5;
if (Bi[0]!='?') {
   if (Bi[0]>' ') return 404;
   }
else Bi++;
if (Hm=strpbrk(Bi,Texts.Eol)) *Hm++ = 0;
Clon->Hm = parseGetParams(Clon,Bi);
if (Hm) parseHeaderMessages(Clon,Hm);
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

static int isLoadMethod(T_cloninfo *Clon, int l) {
char *Bi,*Pp,*Pr;
int F,c,s,m,w;
if (CAS_Srvinfo.fs==0) return -1;
Bi = Clon->Bf;
if (Bi[6]!='?') return 404;
Pp = searchBody(Bi,&c);
if (c<0) return c;
s = l - (Pp - Bi);
for (Pr=Pp-1; isspace(*Pr); Pr--) ;
Pr[1] = Pr[2] = 0;
Pr = strpbrk(Bi,Texts.Eol);
Bi[1] = Bi[2] = 0;
Bi += 7;
Clon->Hm = parseGetParams(Clon,Bi);
if (Clon->Pm[0]==0) return 404;
parseHeaderMessages(Clon,Pr);
c = contentLength(&Clon->Co,CAS_Srvinfo.fs);
if (c<0) return c;
if (CAS_Srvinfo.post) if (CAS_Srvinfo.post(&Clon->Co,c,s)==0)
   return -4;
Pr = Clon->Co.Ufn;
CAS_convertBinaryToName(Pr,3,Clon-Lstclon.Cl);
F = open(Pr,O_WRONLY|O_CREAT|O_TRUNC,0600);
s = s > 0 ? write(F,Pp,s) : 0;
Pr = Clon->Co.Bfo;
l = Srvcfg.norp;
m = Clon->Co.Pet - Pp;
while (s<c) {
      if (l<Srvcfg.norp) {
         close(F);
         if (l<=0) return 0;
         return l > 6 ? -l : -7;
         }
      l = c - s;
      if (l>m) l = m;
      l = recvFromClient(Clon,Pr,l);
      w = write(F,Pr,l);
      s += l;
      }
close(F);
return 200;
}

static int isPostMethod(T_cloninfo *Clon, int l) {
char *Bi,*Pp,*Pr;
int c,s,m;
if (Srvcfg.norp==0) return -1;
Bi = Clon->Bf;
Pp = searchBody(Bi,&c);
if (c<0) return c;
for (Pr=Pp-1; isspace(*Pr); Pr--) ;
Pr[1] = Pr[2] = 0;
Pr = strpbrk(Bi,Texts.Eol);
Bi[1] = Bi[2] = 0;
Bi += 3;
Pr = parseHeaderMessages(Clon,Pr);
s = strlen(Pp) + 1;
memmove(Pr,Pp,s);
Pr[s+1] = 0;
Clon->Pm = Pp = Pr;
l = Clon->Co.Pet - Pp - 4;
m = (Clon->Co.Bfo - Pp) * 3 - 4;
if (l>m) l = m;
m = strlen(Pp);
c = contentLength(&Clon->Co,l);
if (c<0) return c;
if (CAS_Srvinfo.post) if (c>m)
   if (CAS_Srvinfo.post(&Clon->Co,c,m)==0)
      return -4;
if (Pr=CAS_getHeaderValue(&Clon->Co,"Content-type"))
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
      l = recvFromClient(Clon,Pr,l);
      Pr += l;
      s += l;
      }
Pp[s] = Pp[s+1] = 0;
if (Pr) Pr = parseGetParams(Clon,Pp);
return 200;
}

static int receiveRequest(T_cloninfo *Clon) {
static char **Perr = (char **)&Texts;
int k;
char *Bi,*Me;
int (*PostOrLoad)(T_cloninfo *, int);
CAS_getTime(&Clon->Co);
Clon->Co.Bfi = Clon->Ei = Bi = Clon->Bf;
memset(Bi,0,Srvcfg.lbf);
Clon->Co.Bfo = Clon->Po = Bi + Srvcfg.sBfi;
Clon->Co.Bft = Clon->Co.Bfo + Srvcfg.sBfo;
Clon->Co.Pct = Clon->Co.Bft + 1;
Clon->Co.Pet = Clon->Co.Bft + Srvcfg.sBft;
Clon->Pm = Clon->Hm = Bi + 3;
if (memcmp(Clon->Co.Ipc,Srvcfg.Lhst,sizeof(Srvcfg.Lhst))!=0)
   if (CAS_Srvinfo.acco) if (CAS_Srvinfo.acco(Clon->Co.Ipc)==0) {
      abortConnection(&Clon->Co,"Connection refused");
      return 0;
      }
#ifdef _Secure_application_server
if (Clon->cs>0) {
   k = 1;
   if (Clon->Ss=SSL_new(Secinf.Ctx)) {
      SSL_set_fd(Clon->Ss,Clon->sk);
      k = SSL_accept(Clon->Ss);
      if (k<=0) SSL_free(Clon->Ss);
      }
   else k--;
   if (k<=0) {
      Clon->cs = 0;
      Me = secureError(Clon,"Accept");
      abortConnection(&Clon->Co,Me);
      return 0;
      }
   }
#endif
setsockopt(Clon->sk,SOL_SOCKET,SO_RCVTIMEO,&Srvcfg.Trcv,sizeof(Srvcfg.Trcv));
k = 1;
setsockopt(Clon->sk,SOL_TCP,TCP_NODELAY,&k,sizeof(k));
k = recvFromClient(Clon,Clon->Bf,Srvcfg.lbf-4);
Me = "Request timeout";
#ifdef _Secure_application_server
if (Bi[0]==0) Me = secureError(Clon,"Read");
#endif
if (Bi[0]==0) {
   abortConnection(&Clon->Co,Me);
   return 0;
   }
k = memcmp(Bi,"GET /",5);
#ifdef _Secure_application_server
if (Clon->cs==0) {
   if (k==0) return redirectToHttps(Clon);
   return 404;
   }
#endif
if (k==0) return isGetMethod(Clon);
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
k = PostOrLoad(Clon,k);
if (k>0) return k;
if (k<0) {
   k = -k;
   if (k<=6) {
      Me = Perr[k];
      if (k==3) {
         Bi = CAS_getHeaderValue(&Clon->Co,Texts.Clv);
         k = atoi(Bi);
         }
      }
   else Me = "%s %d octets read";
   Bi = Clon->Bf[0] == 'P' ? "POST:" : "LOAD:";
   Me = CAS_sPrintf(&Clon->Co,Me,Bi,k);
   }
abortConnection(&Clon->Co,Me);
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
Ei = ((T_cloninfo *)Conn)->Ei;
memset(Ei,0,Conn->Pet-Ei);
if (Conn->Bfo>=Ei) {
   k = ((Ei - Conn->Bfi) + 1023) & ~1023;
   Ei = Conn->Bfi + k;
   if (Conn->Bfo>Ei)
      ((T_cloninfo *)Conn)->Po = Conn->Bfo = Ei;
   CAS_nPrintf(Conn,CAS_Srvinfo.Rh[0]);
   setitimer(ITIMER_REAL,&Srvcfg.Tpro,NULL);
   CAS_Srvinfo.preq(Conn);
   setitimer(ITIMER_REAL,&Srvcfg.Trst,NULL);
   if (CAS_Srvinfo.ss>0) CAS_updateSession(Conn);
   }
else {
   Ei = CAS_sPrintf(Conn,"Input buffer overflow (%d octets needed)",Ei-Conn->Bfi);
   CAS_nPrintf(Conn,CAS_Srvinfo.Rh[1],Ei);
   }
}

int CAS_serverMutex(CAS_srvconn_t *Conn, int32_t *Mtx, char op) {
int s;
if (op!='L') if (op!='R') return 0;
if (Mtx==NULL) {
   #ifdef _Release_application_server
   ((T_cloninfo *)Conn)->rq = op == 'L' ? 'U' : 0;
   kill(Othinf.pid,SIGCONT);
   sigsuspend(&Othinf.omsk);
   #endif
   return 1;
   }
if (op=='L') {
   while (1) {
         if (__sync_bool_compare_and_swap(Mtx,1,0)) break;
         while (syscall(SYS_futex,Mtx,FUTEX_WAIT|FUTEX_PRIVATE_FLAG,0,NULL,NULL,0)<0) ;
         }
   return 1;
   }
if (__sync_bool_compare_and_swap(Mtx,0,1))
   syscall(SYS_futex,Mtx,FUTEX_WAKE|FUTEX_PRIVATE_FLAG,1,NULL,NULL,0);
return 1;
}

#ifdef _Release_application_server

static T_cloninfo *specialRequest(T_cloninfo *Clon, char req) {
T_cloninfo *Wcln;
for (; Clon->Sb; Clon++)
    if (Clon->rq==req) break;
if (Clon->Sb==NULL) return NULL;
switch (req) {
       case 'Z': Othinf.req = 'Z';
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
if (req!='U')
   CAS_nPrintf(&Clon->Co,"Ok server %s %d (release version) %s\n",Othinf.Npg,Othinf.pid,whichCommand(req));
if (req=='W') {
   sendToClient(&Clon->Co,NULL,0);
   recv(Clon->sk,Clon->Bf,1020,0);
   if (memcmp(Clon->Bf,"Ok data",7)==0) {
      CAS_Srvinfo.data('R');
      CAS_Srvinfo.data('L');
      }
   }
kill(Clon->pd,SIGCONT);
return Clon;
}

static T_cloninfo *cloneAvailable(int ca) {
T_cloninfo *Clon;
int k,r;
do {
   Othinf.req = k = 0;
   Clon = Lstclon.Cl;
   for (; Clon->Sb; Clon++) {
       if (Clon->sk==0) {
          if (ca) {
             Othinf.req = 0;
             return Clon;
             }
          continue;
          }
       r = Clon->rq;
       switch (r) {
              case 0: k |= 1; break;
              case 'U': Othinf.req = 'U';
                        k |= 2; break;
              case 'W': k |= 4; break;
              case 'C': k |= 8; break;
              case 'D': k |= 16; break;
              case 'H': k |= 32; break;
              case 'Z': if (ca>0) {
                           Clon->rq = 0;
                           kill(Clon->pd,SIGCONT);
                           }
                        else k |= 0x400;
                        break;
              }
       }
   if (ca>0) {
      if (k==0) continue;
      }
   else {
      if (k<=1) break;
      }
   if ((k&0x7ffe)==0x400) Othinf.req = 'Z';
   if (k%2>0) {
      if (ca>0 || (k>1)) {
         for (r=0,Clon=Lstclon.Cl; Clon->Sb; Clon++)
             if (Clon->sk>0) if (Clon->rq==0)
                r++;
         if (r>0) sigsuspend(&Othinf.omsk);
         }
      continue;
      }
   if (k & 2) for (Clon=Lstclon.Cl; Clon; Clon++)
      Clon = specialRequest(Clon,'U');
   Clon = Lstclon.Cl;
   if (k & 4) specialRequest(Clon,'W');
   if (k & 0x400) if (specialRequest(Clon,'Z')) {
      Othinf.req = 'Z';
      break;
      }
   if (k & 8) specialRequest(Clon,'C');
   if (k & 16) specialRequest(Clon,'D');
   if (k & 32) specialRequest(Clon,'H');
   if (ca>0) continue;
   if (Othinf.req!='Z') Othinf.req = 0;
   break;
   } while (1);
return NULL;
}

static int performAdminRequest(CAS_srvconn_t *Conn) {
char Ip[INET6_ADDRSTRLEN];
T_cloninfo *Clon;
int s,k;
k = checkAdminRequest(Conn);
if (k==404) return k;
Clon = (T_cloninfo *)Conn;
if (k=='S') {
   CAS_nPrintf(Conn,"Ok server %s %d -show\nClone Socket IP address\n",Othinf.Npg,Clon->pd);
   for (s=0,Clon=Lstclon.Cl; Clon->Sb; s++,Clon++)
       if (Clon->pd) if (Clon->sk) {
          inet_ntop(CAS_Srvinfo.af,&Clon->Co.Ipc,Ip,sizeof(Ip));
          CAS_nPrintf(Conn,"%5d %6d  %s\n",Clon->pd,Clon->sk,Ip);
          }
   for (s=0,Clon=Lstclon.Cl; Clon->Sb; Clon++)
       if (Clon->mi>s) s = Clon->mi;
   CAS_nPrintf(Conn,"Buffer for input strings: %d octets\n",s+4);
   for (s=0,Clon=Lstclon.Cl; Clon->Sb; Clon++)
       if (Clon->mt>s) s = Clon->mt;
   CAS_nPrintf(Conn,"Buffer for temporary strings: %d octets\n",s+4);
   if (Srvcfg.stkT) {
      for (s=0,Clon=Lstclon.Cl; Clon->Sb; Clon++)
          for (k=0; k<Srvcfg.stks; k++)
              if (Clon->Sb[k]!=0) {
                 k = Srvcfg.stks - k;
                 if (k>s) s = k;
                 break;
                 }
      }
   else {
      for (s=0,Clon=Lstclon.Cl; Clon->Sb; Clon++)
          for (k=Srvcfg.stks-1; k>=0; k--)
              if (Clon->Sb[k]!=0) {
                 if (k>s) s = k;
                 break;
                 }
      }
   CAS_nPrintf(Conn,"Maximum stack size: %d\n",(s+4)*sizeof(int));
   k = 'S';
   }
else
if (k=='E') {
   deleteExpiredSession(Conn);
   CAS_nPrintf(Conn,CAS_Srvinfo.Rh[0]);
   }
else {
   Clon->rq = k;
   kill(Othinf.pid,SIGCONT);
   sigsuspend(&Othinf.omsk);
   Clon->rq = 0;
   }
return k;
}

static int userRequest(T_cloninfo *Clon) {
int hk;
stack_t Ss;
Ss.ss_sp = Clon->Sb;
Ss.ss_size = Srvcfg.stks * sizeof(int);
sigaltstack(&Ss,NULL);
setSignal(SIGCONT,processSignal,0);
setSignal(SIGCHLD,processSignal,0);
setSignal(SIGPIPE,SIG_IGN,0);
setSignal(SIGSEGV,processSignal,SA_ONSTACK);
setSignal(SIGFPE,processSignal,0);
setSignal(SIGALRM,processSignal,0);
do {
   if (Othinf.req=='Z') break;
   if (Clon->sk==0) {
      sigsuspend(&Othinf.omsk);
      continue;
      }
   hk = receiveRequest(Clon);
   if (hk==200) {
      #ifdef _Secure_application_server
      Clon->Co.Bfi[1] = 's';
      #endif
      processRequest(&Clon->Co);
      }
   if (hk==404) hk = performAdminRequest(&Clon->Co);
   if (hk==404) CAS_nPrintf(&Clon->Co,"%s Not found\n",CAS_Srvinfo.Rh[1]);
   sendToClient(&Clon->Co,NULL,0);
   closeSocket(Clon);
   kill(Othinf.pid,SIGCONT);
   } while (1);
return Clon->pd = Clon->rq = 0;
}

static void serverCycle(void) {
T_cloninfo *Clon;
struct pollfd *Ppo;
int *Sb, k, n, s;
char *Ms;
setSignal(SIGCONT,processSignal,0);
setSignal(SIGCHLD,processSignal,0);
sigemptyset(&Othinf.mask);
sigaddset(&Othinf.mask,SIGCONT);
sigaddset(&Othinf.mask,SIGCHLD);
sigprocmask(SIG_BLOCK,&Othinf.mask,&Othinf.omsk);
CAS_Srvinfo.data('L');
CAS_Srvinfo.html('L');
Othinf.err = initServer();
Ms = "";
#ifdef _Secure_application_server
Ppo = Othinf.Pof + 1;
Ppo->fd = checkingPort(Srvcfg.Lpo[1],Lstclon.nc,"only internet (secure) requests");
Ppo->events = POLLIN;
Othinf.nls++;
Ms = " and secure";
#endif
fprintf(stderr,"Server active, IPv%d release%s version\n",CAS_Srvinfo.af==AF_INET?4:6,Ms);
do {
   Othinf.Pof[0].revents = Othinf.Pof[1].revents = n = 0;
   if (ppoll(Othinf.Pof,Othinf.nls,NULL,&Othinf.omsk)>0)
      for (k=0,Ppo=Othinf.Pof; k<Othinf.nls; k++,Ppo++) {
          s = Ppo->revents & POLLIN;
          if (s==0) continue;
          s = sizeof(Othinf.San);
          s = accept(Ppo->fd,(struct sockaddr *)&Othinf.San,&s);
          if (s<0) continue;
          n++;
          Clon = cloneAvailable(1);
          memset(&Clon->Co,0,sizeof(CAS_srvconn_t));
          memcpy(Clon->Co.Ipc,Srvcfg.Psa,Srvcfg.lsa);
          Clon->sk = s;
          Clon->cs = k;
          if (Clon->pd==0) {
             Sb = Clon->Sb + Srvcfg.stkT;
             Clon->pd = clone((int (*)(void *))userRequest,Sb,CLONE_FS|CLONE_FILES|CLONE_VM|SIGCHLD,Clon);
             }
          else kill(Clon->pd,SIGCONT);
          }
   if (n==0) cloneAvailable(0);
   } while (Othinf.req!='Z');
for (Clon=Lstclon.Cl; Clon->Sb; Clon++)
    kill(Clon->pd,SIGCONT);
kill(Clon[1].pd,SIGCONT);
}

#else

static void serverCycle(void) {
T_cloninfo *Clon;
int hk;
CAS_Srvinfo.data('L');
CAS_Srvinfo.html('L');
setSignal(SIGALRM,processSignal,0);
setSignal(SIGCONT,processSignal,0);
setSignal(SIGCHLD,processSignal,0);
initServer();
fprintf(stderr,"Server active, IPv%d debug version\n",CAS_Srvinfo.af==AF_INET?4:6);
Clon = Lstclon.Cl;
do {
   hk = sizeof(Othinf.San);
   hk = accept(Othinf.Pof[0].fd,(struct sockaddr *)&Othinf.San,&hk);
   if (hk<0) continue;
   memset(Clon,0,sizeof(CAS_srvconn_t));
   memcpy(Clon->Co.Ipc,Srvcfg.Psa,Srvcfg.lsa);
   Clon->sk = hk;
   hk = receiveRequest(Clon);
   if (hk==200) processRequest(&Clon->Co);
   else
   if (hk==404) {
      hk = checkAdminRequest(&Clon->Co);
      if (hk<='Z') {
         switch (hk) {
                case 'C': readConfig(NULL);
                          explodeHeaders();
                          break;
                case 'D': CAS_Srvinfo.data('R');
                          CAS_Srvinfo.data('L');
                          break;
                case 'H': CAS_Srvinfo.html('R');
                          CAS_Srvinfo.html('L');
                          break;
                case 'S': CAS_nPrintf(&Clon->Co,"Buffer for input strings: %d octets\n",Clon->mi+4);
                          CAS_nPrintf(&Clon->Co,"Buffer for temporary strings: %d octets\n",Clon->mt+4);
                          break;
                case 'E': deleteExpiredSession(&Clon->Co);
                          break;
                }
         CAS_nPrintf(&Clon->Co,"Ok server %s %d (debug version) %s\n",Othinf.Npg,Othinf.pid,whichCommand(hk));
         }
      if (hk=='W') {
         sendToClient(&Clon->Co,NULL,0);
         recv(Clon->sk,Clon->Bf,1020,0);
         if (memcmp(Clon->Bf,"Ok data",7)==0) {
            CAS_Srvinfo.data('R');
            CAS_Srvinfo.data('L');
            }
         }
      if (hk==404) CAS_nPrintf(&Clon->Co,"%s Not found\n",CAS_Srvinfo.Rh[1]);
      }
   sendToClient(&Clon->Co,NULL,0);
   closeSocket(Clon);
   } while (hk!='Z');
}

#endif

static void dummyLoadFree(char op) { }

int main(int agc, char **Agv) {
int o;
CAS_Srvinfo.Nv = "";
CAS_Srvinfo.data = CAS_Srvinfo.html = dummyLoadFree;
CAS_registerUserSettings();
if (CAS_Srvinfo.preq==NULL) {
   fputs("Process request (CAS_Srvinfo.prq) not defined\n",stderr);
   exit(1);
   }
Othinf.pid = getpid();
#ifdef _Secure_application_server
OpenSSL_add_all_algorithms();
SSL_load_error_strings();
ERR_load_BIO_strings();
Secinf.Mtd = (SSL_METHOD *)TLS_server_method();
#endif
readConfig(Agv[0]);
o = 6;
if (agc==2)
   for (o=0; Cmds[o]; o++)
       if (strcmp(Agv[1],Cmds[o])==0) break;
if (Cmds[o]==NULL) {
   fputs("The argument of command line must be:\n",stderr);
   fprintf(stderr,"%s\tStart server\n",Cmds[0]);
   fprintf(stderr,"%s\tStop server\n",Cmds[1]);
   fprintf(stderr,"%s\tReload config\n",Cmds[2]);
   fprintf(stderr,"%s\tReload data\n",Cmds[3]);
   fprintf(stderr,"%s\tReload html\n",Cmds[4]);
   fprintf(stderr,"%s\tShow info\n",Cmds[5]);
   return 1;
   }
if (o==0) {
   if (CAS_Srvinfo.ss>0) {
      sprintf(Othinf.Buf,"%s.ssn",Othinf.Npg);
      CAS_initSessionSupport(Othinf.Buf);
      }
   Srvcfg.stkT = Srvcfg.stks; /* drop this line if stack grows upward */
   serverCycle();
   }
else processCommand(Cmds[o]);
return 0;
}
