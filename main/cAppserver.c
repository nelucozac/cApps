/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
 The web server application will accept GET, POST and PUT requests.
 For enctype, only application/x-www-form-urlencoded is accepted.
 Use PUT method to upload files.
 See attached documentation for details.
*/

#include "cAppserver.h"

typedef struct {
        SRV_conn Co;
        int *Sb, pd, mt, mi, sk;
        #ifdef _Secure_application_server
        SSL *ssl;
        #endif
        char *Bf, *Pm, *Hm, rq;
        } T_cloninfo;

SRV_info Srvinfo;


static char *Cmds[] = { "-start", "-stop", "-cnfg", "-data", "-html", "-show", NULL, "-wait" } ;

static struct {
       int stks, sBfi, sBfo, sBft, port, stkT;
       unsigned char Lhst[16];
       void *Psa;
       int norp, lbf, lsa;
       char *Pswd, Ncfg[4096], Herr[256], *Mtl;
       struct itimerval Tpro, Trst;
       struct timeval Trcv;
       } Srvcfg;

static struct {
       struct rlimit Rlim;
       union { struct sockaddr_in Sao; struct sockaddr_in6 San; } ;
       sigset_t mask, omsk;
       time_t uts;
       struct timespec Rtm;
       char *Cfg, *Npg, Buf[4096];
       int pid, dsk, err;
       char req;
       } Othinf;

static struct {
       T_cloninfo *Cl; int nc;
       } Lstclon;

#ifdef _Secure_application_server
static struct {
       union { struct sockaddr_in Sao; struct sockaddr_in6 San; } ;
       int port, dsk;
       void *Psa;
       char Nkey[4096];
       SSL_METHOD *Mtd;
       SSL_CTX *Ctx;
       } Secinf;
#endif

static void errorMessage(char *, int);

void convertBinaryToName(char *Nam, int np, unsigned long long val) {
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

static int checkAdminRequest(SRV_conn *Conn) {
char *Bf;
if (memcmp(Conn->Ipc,Srvcfg.Lhst,Srvinfo.af==AF_INET?4:16)!=0)
   return 404;
Bf = strchr(Conn->Bfi,' ');
if (Bf==NULL) return 404;
if (strcmp(Bf+1,Srvcfg.Pswd)!=0) return 404;
Bf = Conn->Bfi;
if (memcmp(Bf,Cmds[2],5)==0) return 'C';
if (memcmp(Bf,Cmds[3],5)==0) return 'D';
if (memcmp(Bf,Cmds[4],5)==0) return 'H';
if (memcmp(Bf,Cmds[5],5)==0) return 'S';
if (memcmp(Bf,Cmds[7],5)==0) return 'W';
if (memcmp(Bf,Cmds[1],5)==0) return 'Z';
return 404;
}

static int recvFromClient(T_cloninfo *Clon, void *Buf, int len) {
#ifdef _Secure_application_server
int k;
k = SSL_read(Clon->Ss,Buf,len);
/* check for errors */
return k;
#else
return recv(Clon->sk,Buf,len,0);
#endif
}

static void sendToClient(SRV_conn *Conn, char *Bf, int ls) {
int s;
if (Bf==NULL) {
   Bf = Conn->Bfo;
   ls = Conn->Pco - Bf;
   }
if (ls>0) {
   do {
      #ifdef _Secure_application_server
      s = SSL_write(((T_cloninfo *)Conn)->Ss,Bf,ls);
      /* check for errors */
      #else
      s = send(((T_cloninfo *)Conn)->sk,Bf,ls,0);
      #endif
      if (s==ls) break;
      if (s<0) break;
      Bf += s;
      ls -= s;
      } while (1);
   memset(Conn->Bfo,0,Conn->Bft-Conn->Bfo);
   Conn->Pco = Conn->Bfo;
   }
}

char *buildMimeTypeList(char *Cfg) {
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

void sendFileToClient(SRV_conn *Conn, char *Fnm, char *Rhd, int (*valid)(char *)) {
int fh,fs,s;
char *F,*E,*C,*P;
fh = 0;
F = Fnm;
if (P=strrchr(F,'/')) F = P + 1;
if (valid) if (valid(Fnm)==0)
   fh--;
if (fh==0) {
   P = Srvcfg.Mtl;
   E = strrchr(F,'.');
   if (E==NULL) E = "";
   do {
      s = *P != '*' ? strcasecmp(P,E) == 0 : 1;
      C = endOfString(P,1);
      if (s) break;
      P = endOfString(C,1);
      } while (*P);
   if (*C!='?') {
      fh = open(Fnm,O_RDONLY);
      if (fh>0) {
         fs = lseek(fh,0,SEEK_END);
         lseek(fh,0,SEEK_SET);
         }
      }
   else errno = EACCES;
   }
Conn->Pco = Conn->Bfo;
if (fh>0) {
   nPrintf(Conn,Rhd,F,C,fs);
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
else nPrintf(Conn,"%s%s",Srvinfo.Rh[1],strerror(errno));
}

static void abortConnection(SRV_conn *Conn, char *Ms) {
struct tm Tim;
int r;
inet_ntop(Srvinfo.af,Conn->Ipc,Conn->Bft,INET6_ADDRSTRLEN);
Conn->Pco = Conn->Bfo;
localtime_r(&Conn->uts,&Tim);
nPrintf(Conn,"%d/%02d/%02d %d:%02d %s from %s\n",Tim.tm_year+1900,Tim.tm_mon+1,Tim.tm_mday,Tim.tm_hour,Tim.tm_min,Ms,Conn->Bft);
#ifdef _Release_application_server
r = write(Othinf.err,Conn->Bfo,strlen(Conn->Bfo));
Conn->Pco = Conn->Bfo;
nPrintf(Conn,"%s%s\n",Srvinfo.Rh[1],Ms);
#else
fputs(Conn->Bfo,stderr);
#endif
}

static void explodeHeaders(void) {
static char Ht[] = "HTTP", Nl[] = "\n\n";
char *P, *S, **Out;
int k;
if (Srvinfo.Rh==NULL) {
   k = 0;
   P = Othinf.Cfg;
   do {
      if (memcmp(P,Ht,4)!=0) break;
      k++;
      P = strstr(P,Nl);
      while (isspace(*P)) P++;
      } while (1);
   Srvinfo.Rh = calloc(k+1,sizeof(char *));
   if (Srvinfo.Rh==NULL) errorMessage("explodeHeaders",errno);
   }
Out = Srvinfo.Rh;
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
strcpy(Srvcfg.Herr,Srvinfo.Rh[1]);
strcat(Srvcfg.Herr,"- ");
Srvinfo.Rh[1] = Srvcfg.Herr;
}

#ifdef _Release_application_server

static void errorMessage(char *Ms, int er) {
T_cloninfo *Clon;
sprintf(Othinf.Buf,"\nInternal error: %s, %s\n",Ms,strerror(er));
fputs(Othinf.Buf,stderr);
if (Othinf.err>0) er = write(Othinf.err,Othinf.Buf,strlen(Othinf.Buf));
if (Lstclon.Cl) {
   for (Clon=Lstclon.Cl; Clon->Sb; Clon++)
       if (Clon->pd>0) kill(Clon->pd,SIGKILL);
   }
exit(1);
}

static void processSignal(int snl) {
int p;
char *Me,*P;
struct tm Tim;
T_cloninfo *Clon;
if (snl==SIGCONT) return;
if (snl==SIGCHLD) {
   while (waitpid(-1,NULL,__WALL|WNOHANG)>0) ;
   return;
   }
p = getpid();
for (Clon=Lstclon.Cl; Clon->Sb; Clon++)
    if (Clon->pd==p) break;
if (!Clon->Sb || !Clon->Bf) exit(1);
if (snl==SIGALRM) if (Clon->Co.tmo==0) {
   Clon->Co.tmo++;
   return;
   }
if (Clon->Co.Bfo==Clon->Co.Pco)
   nPrintf(&Clon->Co,Srvinfo.Rh[1]);
Me = sys_siglist[snl];
nPrintf(&Clon->Co,Me);
sendToClient(&Clon->Co,NULL,0);
close(Clon->sk);
Clon->Co.Pct = Clon->Co.Bft + 1;
localtime_r(&Clon->Co.uts,&Tim);
Me = Clon->Co.Bfo + sprintf(Clon->Co.Bfo,"%d/%02d/%02d %d:%02d %s\n",Tim.tm_year+1900,
                            Tim.tm_mon+1,Tim.tm_mday,Tim.tm_hour,Tim.tm_min,Me);
for (P=Clon->Pm; *P; ) {
    Me += sprintf(Me," %s",convertString(&Clon->Co,P,'U'));
    P = endOfString(P,1);
    Me += sprintf(Me,"=%s",convertString(&Clon->Co,P,'U'));
    Clon->Co.Pct = Clon->Co.Bft + 1;
    P = endOfString(P,1);
    }
Me += sprintf(Me,"\n");
p = write(Othinf.err,Clon->Co.Bfo,Me-Clon->Co.Bfo);
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

static void nPuts(SRV_conn *Conn, char *Buf, int len) {
int d;
do {
   d = Conn->Bft - Conn->Pco;
   if (d>len) break;
   memcpy(Conn->Pco,Buf,d);
   Conn->Pco += d;
   sendToClient(Conn,NULL,0);
   Buf += d;
   len -= d;
   } while (1);
if (len>0) {
   memcpy(Conn->Pco,Buf,len);
   Conn->Pco += len;
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
   if (P-27>Cnv) P = endOfString(Cnv,0);
   if (*P) *P = 0;
   }
}

void nPrintf(SRV_conn *Conn, char *Fmt, ... ) {
union { int n; long long l; long double e; char *C; } V;
va_list Ap;
char *Fpv,Cnv[32],f;
int v,w;
va_start(Ap,Fmt);
while (*Fmt) {
      Fpv = Fmt; Fmt = strchr(Fpv,'%');
      if (Fmt==NULL) Fmt = endOfString(Fpv,0);
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

char *cPrintf(SRV_conn *Conn, char *Fmt, ... ) {
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

char *loadTextFile(char *Nft) {
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

int explodeHtm(char *Htmi, void *Htmo, int siz) {
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
   P = endOfString(P,1);
   } while (*P);
return 1;
}

long double getTime(SRV_conn *Conn) {
struct timespec Tms;
long double dt;
clock_gettime(CLOCK_MONOTONIC_COARSE,&Tms);
dt = (long double)(Tms.tv_sec - Othinf.Rtm.tv_sec) + (long double)(Tms.tv_nsec - Othinf.Rtm.tv_nsec)
     / 1000000000.0;
if (Conn) if (Conn->uts==0)
   Conn->uts = Othinf.uts + (long long)dt;
return dt;
}

char *convertString(SRV_conn *Conn, char *Str, char op) {
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
d = socket(Srvinfo.af,SOCK_STREAM,IPPROTO_TCP);
if (d<0) errorMessage("socket",errno);
inet_pton(Srvinfo.af,Othinf.Buf,&Othinf.San);
fprintf(stderr,"Checking port %d, %s\n",p,M);
if (Srvinfo.af==AF_INET) {
   Othinf.Sao.sin_family = Srvinfo.af;
   Othinf.Sao.sin_port = htons(p);
   }
else {
   Othinf.San.sin6_family = Srvinfo.af;
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
SRV_conn *Conn;
char *Ms;
int k;
Othinf.Rlim.rlim_cur = Othinf.Rlim.rlim_max = Srvcfg.stks * sizeof(int);
setrlimit(RLIMIT_STACK,&Othinf.Rlim);
explodeHeaders();
#ifdef _Release_application_server
sprintf(Othinf.Buf,"%s.err",Othinf.Npg);
k = open(Othinf.Buf,O_APPEND|O_CREAT|O_WRONLY|O_DSYNC,0600);
if (k<0) errorMessage("errLog",errno);
#else
k = 0;
#endif
#ifdef _Secure_application_server
Ms = "only admin requests";
#else
Ms = "admin and internet requests";
#endif
Othinf.dsk = checkingPort(Srvcfg.port,Lstclon.nc,Ms);
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
      if (Pv.N=va_arg(Prms,int *)) *Pv.N = atoi(Ps);
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
      inet_pton(Srvinfo.af,Ps,Pv.A);
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
   n = 0;
   #ifdef _Secure_application_server
   n++;
   SSL_CTX_free(Secinf.Ctx);
   #endif
   for (Clon=Lstclon.Cl+n; Clon->Sb; Clon++)
       free(Clon->Bf);
   free(Othinf.Cfg);
   }
Othinf.Cfg = Ps = loadTextFile(Srvcfg.Ncfg);
Ps = strstr(Ps,"- Server ");
Ps = strchr(Ps,'\n');
Ps = scanConfig(Ps,"sd",&Srvcfg.Pswd,&n);
if (n==4) {
   Srvinfo.af = AF_INET;
   Srvcfg.Psa = &Othinf.Sao.sin_addr.s_addr;
   Srvcfg.lsa = 4;
   }
else {
   Srvinfo.af = AF_INET6;
   Srvcfg.Psa = Othinf.San.sin6_addr.s6_addr;
   Srvcfg.lsa = 16;
   }
Ps = scanConfig(Ps,"aa",Srvcfg.Psa,Srvcfg.Lhst);
#ifdef _Secure_application_server
Ps = scanConfig(Ps,"dd",&Secinf.port,&Srvcfg.port);
#else
Ps = scanConfig(Ps,"dd",&Srvcfg.port,NULL);
#endif
Ps = scanConfig(Ps,"dtddddtddd",&n,&Srvcfg.Tpro.it_value.tv_sec,&s,&Srvcfg.sBfi,&Srvcfg.sBfo,&Srvcfg.sBft,
                &Srvcfg.Trcv.tv_sec,&Srvcfg.norp,&Srvinfo.fs,&Srvinfo.se);
Srvcfg.Tpro.it_interval.tv_sec = 1;
if (Lstclon.nc==0) {
   #ifdef _Secure_application_server
   n++;
   #endif
   #ifndef _Release_application_server
   n = 1;
   #endif
   Lstclon.nc = n;
   Srvcfg.stks = ((s + 1023) & 0xffffc00) / sizeof(int);
   Lstclon.Cl = calloc(n+1,sizeof(T_cloninfo));
   if (Lstclon.Cl==NULL) errorMessage(Ecf,errno);
   for (s=0,Clon=Lstclon.Cl; s<n; s++,Clon++) {
       Clon->Sb = calloc(Srvcfg.stks,sizeof(int));
       if (Clon->Sb==NULL) errorMessage(Ecf,errno);
       }
   }
Srvcfg.sBfi = (Srvcfg.sBfi + 1023) & 0xffffc00;
if (Srvcfg.norp>0) {
   Srvcfg.norp = (Srvcfg.norp + 1023) & 0xffffc00;
   if (Srvcfg.norp>=Srvcfg.sBfi) Srvcfg.sBfi = Srvcfg.norp + 1024;
   }
Srvcfg.sBfo = (Srvcfg.sBfo + 1023) & 0xffffc00;
if (Srvcfg.sBfo<=Srvcfg.sBfi) Srvcfg.sBfo = Srvcfg.sBfi + 1024;
Srvcfg.sBft = (Srvcfg.sBft + 1023) & 0xffffc00;
Srvcfg.lbf = Srvcfg.sBfi + Srvcfg.sBfo + Srvcfg.sBft;
if (Lstclon.nc>0) {
   n = 0;
   #ifdef _Secure_application_server
   n++;
   #endif
   for (Clon=Lstclon.Cl+n; Clon->Sb; Clon++) {
       Clon->Bf = calloc(Srvcfg.lbf,1);
       if (Clon->Bf==NULL) errorMessage(Ecf,errno);
       }
   }
if (Srvinfo.cnfg) {
   Ps = strstr(Ps,"- User ");
   Ps = strchr(Ps,'\n');
   while (isspace(*Ps)) Ps++;
   Srvinfo.cnfg(Ps);
   }
time(&Othinf.uts);
if (clock_gettime(CLOCK_MONOTONIC_COARSE,&Othinf.Rtm)<0) {
   errorMessage(Ecf,errno);
   exit(1);
   }
#ifdef _Secure_application_server
Secinf.Ctx = SSL_CTX_new(Secinf.Mtd);
if (Secinf.Mtx==NULL) {
   /* error creating ssl context */
   }
if (SSL_CTX_use_certificate_file(Secinf.Ctx,Secinf.Nkey,SSL_FILETYPE_PEM)<=0) {
   /* error certificate file */
   }
if (SSL_CTX_use_PrivateKey_file(Secinf.Ctx,Secinf.Nkey,SSL_FILETYPE_PEM)<=0) {
   /* error private key file */
   }
#endif
}

static void processCommand(char *Cmd) {
time_t ti;
int s;
sprintf(Othinf.Buf,"%s %s",Cmd,Srvcfg.Pswd);
Othinf.dsk = socket(Srvinfo.af,SOCK_STREAM,IPPROTO_TCP);
if (Othinf.dsk<0) errorMessage("",errno);
if (Srvinfo.af==AF_INET) {
   Othinf.Sao.sin_family = Srvinfo.af;
   Othinf.Sao.sin_port = htons(Srvcfg.port);
   memcpy(&Othinf.Sao.sin_addr.s_addr,Srvcfg.Lhst,4);
   }
else {
   Othinf.San.sin6_family = Srvinfo.af;
   Othinf.San.sin6_port = htons(Srvcfg.port);
   memcpy(Othinf.San.sin6_addr.s6_addr,Srvcfg.Lhst,16);
   }
ti = time(NULL);
s = 0;
while (connect(Othinf.dsk,(struct sockaddr *)&Othinf.San,sizeof(Othinf.San))<0) {
      if (time(NULL)-ti>Srvcfg.Trcv.tv_sec) s = ETIMEDOUT;
      if (errno==ECONNREFUSED) s = errno;
      if (s!=0) errorMessage("connect",s);
      sleep(1);
      }
send(Othinf.dsk,Othinf.Buf,strlen(Othinf.Buf),0);
Srvcfg.Trcv.tv_sec += Srvcfg.Tpro.it_value.tv_sec;
setsockopt(Othinf.dsk,SOL_SOCKET,SO_RCVTIMEO,&Srvcfg.Trcv,sizeof(Srvcfg.Trcv));
do {
   memset(Othinf.Buf,0,sizeof(Othinf.Buf));
   recv(Othinf.dsk,Othinf.Buf,sizeof(Othinf.Buf)-1,0);
   if (Othinf.Buf[0]==0) break;
   s++;
   fprintf(stderr,"%s",Othinf.Buf);
   } while (1);
if (s==0) perror("No response");
close(Othinf.dsk);
}

char *getParamName(SRV_conn *Conn, char *From) {
char *P;
if (P=From) {
   P = endOfString(From,1);
   P = endOfString(P,1);
   }
else P = ((T_cloninfo *)Conn)->Pm;
return *P ? P : NULL;
}

char *getParamValue(SRV_conn *Conn, char *Name, char *From) {
char *P,*Q;
if (From) {
   P = From;
   P = endOfString(P,1);
   }
else P = ((T_cloninfo *)Conn)->Pm;
do {
   Q = endOfString(P,1);
   if (strcmp(P,Name)==0) return Q;
   P = endOfString(Q,1);
   } while (*P);
return NULL;
}

char *getLastParamValue(SRV_conn *Conn, char *Name) {
char *F,*P;
F = NULL;
do {
   P = getParamValue(Conn,Name,F);
   if (P==NULL) break;
   F = P;
   } while (1);
return F ? F : Srvinfo.Nv;
}

char *getHeaderName(SRV_conn *Conn, char *From) {
char *P;
if (From) {
   P = endOfString(From,1);
   P = endOfString(P,1);
   }
else P = ((T_cloninfo *)Conn)->Hm;
return *P ? P : NULL;
}

char *getHeaderValue(SRV_conn *Conn, char *Name) {
char *P,*Q;
P = ((T_cloninfo *)Conn)->Hm;
do {
   Q = endOfString(P,1);
   if (strcasecmp(P,Name)==0) return Q;
   P = Q;
   } while (*P);
return NULL;
}

static struct { char *Eol, *Prj, *Mcl, *Clb, *Rto, *Mhd, *Ctn, *Zzz, *Clv; } Textp = {
       "\r\n", "Post / Put rejected", "Missing Content-length",
       "Content-length too big (%d)", "Post / Put timeout",
       "Missing end of headers", "Content-type not allowed",
       NULL, "Content-length" } ;

static char *postError(SRV_conn *Conn, int k) {
static char **Perr = (char **)&Textp;
char *P;
k = -k;
if (k>6) return cPrintf(Conn,"%d octets read",k);
if (k==3) {
   P = getHeaderValue(Conn,Textp.Clv);
   return cPrintf(Conn,Textp.Clb,atoi(P));
   }
return Perr[k];
}

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
         c = s % 2 > 0 || v > ' ' ? v : '_';
         }
      *Ds++ = c;
      } while (1);
   *Ds++ = 0;
   s++;
   } while (1);
*Ds++ = 0;
*Ds++ = 0;
s = Ds - Clon->Bf;
if (Clon->mi<s) Clon->mi = s;
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
return Ds;
}

static int isGetMethod(T_cloninfo *Clon) {
char *Bi,*Hm;
Bi = Clon->Bf;
if (Srvinfo.rwrl) Srvinfo.rwrl(&Clon->Co);
Bi[1] = Bi[2] = 0;
Bi += 5;
if (Bi[0]!='?') {
   if (Bi[0]>' ') return 404;
   }
else Bi++;
if (Hm=strpbrk(Bi,Textp.Eol)) *Hm++ = 0;
Clon->Hm = parseGetParams(Clon,Bi);
if (Hm) parseHeaderMessages(Clon,Hm);
memset(Clon->Co.Bfo-2,0,Srvcfg.sBfo+Srvcfg.sBft+2);
return 200;
}

static int contentLength(SRV_conn *Conn, int lM) {
char *Hv;
int l;
l = 0;
if (Hv=getHeaderValue(Conn,Textp.Clv))
   l = atoi(Hv);
if (l<=0) return -2;
if (l>lM) return -3;
return l;
}

static char *searchBody(char *Bi, int *k) {
char c,d;
*k = 1;
Bi = strpbrk(Bi,Textp.Eol);
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

static int isPutMethod(T_cloninfo *Clon, int l) {
char *Bi,*Pp,*Pr;
int F,c,s,m,w;
if (Srvinfo.fs==0) return -1;
Bi = Clon->Bf;
if (Bi[5]!='?') return 404;
Pp = searchBody(Bi,&c);
if (c<0) return c;
s = l - (Pp - Bi);
for (Pr=Pp-1; isspace(*Pr); Pr--) ;
Pr[1] = Pr[2] = 0;
Pr = strpbrk(Bi,Textp.Eol);
Bi[1] = Bi[2] = 0;
Bi += 6;
Clon->Hm = parseGetParams(Clon,Bi);
if (Clon->Pm[0]==0) return 404;
parseHeaderMessages(Clon,Pr);
c = contentLength(&Clon->Co,Srvinfo.fs);
if (c<0) return c;
if (Srvinfo.post) if (Srvinfo.post(&Clon->Co,c,-1)==0)
   return -1;
Pr = Clon->Co.Ufn;
convertBinaryToName(Pr,3,Clon-Lstclon.Cl);
F = open(Pr,O_WRONLY|O_CREAT|O_TRUNC,0600);
s = s > 0 ? write(F,Pp,s) : 0;
Pr = Clon->Co.Bfo;
l = Srvcfg.norp;
m = Clon->Co.Pet - Pp;
while (s<c) {
      if (l<Srvcfg.norp) {
         close(F);
         if (l<=0) return -4;
         return l > 6 ? -l : -7;
         }
      l = c - s;
      if (l>m) l = m;
      l = recvFromClient(Clon,Pr,l);
      w = write(F,Pr,l);
      s += l;
      }
close(F);
memset(Pr-2,0,Srvcfg.sBfo+Srvcfg.sBft+2);
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
Pr = strpbrk(Bi,Textp.Eol);
Bi[1] = Bi[2] = 0;
Bi += 3;
Pr = parseHeaderMessages(Clon,Pr);
s = strlen(Pp) + 1;
memmove(Pr,Pp,s);
Pr[s+1] = 0;
Clon->Pm = Pp = Pr;
l = Clon->Co.Pet - Pp - 4;
m = (Clon->Co.Bfo - Pp) * 3;
if (l>m) l = m;
c = contentLength(&Clon->Co,l);
if (c<0) return c;
if (Srvinfo.post) if (Srvinfo.post(&Clon->Co,c,l)==0)
   return -1;
if (Pr=getHeaderValue(&Clon->Co,"Content-type"))
   if (strcasecmp(Pr,"application/x-www-form-urlencoded")!=0)
      return -6;
s = strlen(Pp);
Pr = Pp;
l = Srvcfg.norp;
while (s<c) {
      if (l<Srvcfg.norp) {
         if (l<=0) return -4;
         return l > 6 ? -l : -7;
         }
      l = c - s;
      l = recvFromClient(Clon,Pr,l);
      Pr += l;
      s += l;
      }
Pp[s] = Pp[s+1] = 0;
if (Pr) Pr = parseGetParams(Clon,Pp);
if (Pr>=Clon->Co.Bfo) return -3;
memset(Pr-2,0,Srvcfg.sBfo+Srvcfg.sBft+2);
return 200;
}

static void closeSocket(T_cloninfo *Clon) {
#ifdef _Secure_application_server
if (Clon->Co.ssl) SSL_free(Clon->Co.ssl);
#endif
close(Clon->sk);
Clon->sk = Clon->rq = 0;
}

static int receiveRequest(T_cloninfo *Clon) {
int k;
char *Bi;
int (*PostOrPut)(T_cloninfo *, int);
Clon->Co.tim = getTime(&Clon->Co);
Clon->Co.Bfi = Bi = Clon->Bf;
#ifdef _Secure_application_server
k = 0;
if (Clon->Co.ssl=SSL_new(Othinf.Ctx)) {
   SSL_set_fd(Clon->Co.ssl,Clon->sk);
   if (SSL_accept(Clon->Co.ssl)<=0) k++;
   }
if (k>0) {
   /* detail error */
   abortConnection(&Clon->Co,"SSL accept");
   return 0;
   }
#endif
memset(Bi,0,Srvcfg.lbf);
Clon->Co.Bfo = Clon->Co.Pco = Bi + Srvcfg.sBfi;
Clon->Co.Bft = Clon->Co.Bfo + Srvcfg.sBfo;
Clon->Co.Pct = Clon->Co.Bft + 1;
Clon->Co.Pet = Clon->Co.Bft + Srvcfg.sBft;
Clon->Pm = Clon->Hm = Bi + 3;
if (memcmp(Clon->Co.Ipc,Srvcfg.Lhst,sizeof(Srvcfg.Lhst))!=0)
   if (Srvinfo.acco) if (Srvinfo.acco(Clon->Co.Ipc)==0) {
      abortConnection(&Clon->Co,"Connection refused");
      return 0;
      }
setsockopt(Clon->sk,SOL_SOCKET,SO_RCVTIMEO,&Srvcfg.Trcv,sizeof(Srvcfg.Trcv));
k = 1;
setsockopt(Clon->sk,SOL_TCP,TCP_NODELAY,&k,sizeof(k));
k = recvFromClient(Clon,Clon->Bf,Srvcfg.lbf-4);
if (Bi[0]==0) {
   abortConnection(&Clon->Co,"Request timeout");
   return 0;
   }
if (memcmp(Bi,"GET /",5)==0)
   return isGetMethod(Clon);
PostOrPut = NULL;
if (memcmp(Bi,"POST /",6)==0)
   PostOrPut = isPostMethod;
if (memcmp(Bi,"PUT /",5)==0)
   PostOrPut = isPutMethod;
if (PostOrPut) {
   k = PostOrPut(Clon,k);
   if (k>0) return k;
   abortConnection(&Clon->Co,postError(&Clon->Co,k));
   return 0;
   }
return 404;
}

static void setSignal(int snl, void (*sHnd)(int), int fl) {
struct sigaction Act;
memset(&Act,0,sizeof(Act));
Act.sa_handler = sHnd;
Act.sa_flags = fl;
sigaction(snl,&Act,NULL);
}

static void processRequest(SRV_conn *Conn) {
nPrintf(Conn,Srvinfo.Rh[0]);
setitimer(ITIMER_REAL,&Srvcfg.Tpro,NULL);
Srvinfo.preq(Conn);
setitimer(ITIMER_REAL,&Srvcfg.Trst,NULL);
if (Srvinfo.ss>0) writeSession(Conn);
}

int serverMutex(SRV_conn *Conn, int *Mtx, char op) {
if (Mtx==NULL) {
   if (op!='L') if (op!='R') return 0;
   #ifdef _Release_application_server
   ((T_cloninfo *)Conn)->rq = op == 'L' ? 'U' : 0;
   kill(Othinf.pid,SIGCONT);
   sigsuspend(&Othinf.omsk);
   #endif
   return 1;
   }
if (op=='L') {
   if (Mtx==NULL) return 1;
   while (1) {
         if (__sync_bool_compare_and_swap(Mtx,1,0))
            break;
         while (syscall(SYS_futex,Mtx,FUTEX_WAIT|FUTEX_PRIVATE_FLAG,0,NULL,NULL,0)<0) ;
         }
   return 1;
   }
if (op=='R') {
   if (Mtx==NULL) return 1;
   if (__sync_bool_compare_and_swap(Mtx,0,1))
      syscall(SYS_futex,Mtx,FUTEX_WAKE|FUTEX_PRIVATE_FLAG,1,NULL,NULL,0);
   return 1;
   }
return 0;
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
       case 'D': Srvinfo.data('R');
                 Srvinfo.data('L');
                 break;
       case 'H': Srvinfo.html('R');
                 Srvinfo.html('L');
                 break;
       }
if (req!='U')
   nPrintf(&Clon->Co,"Ok server %s %d (release version) %s\n",Othinf.Npg,Othinf.pid,whichCommand(req));
if (req=='W') {
   recv(Clon->sk,Clon->Bf,1020,0);
   if (memcmp(Clon->Bf,"Ok data",7)==0) {
      Srvinfo.data('R');
      Srvinfo.data('L');
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
   for (Clon=Lstclon.Cl; Clon->Sb; Clon++) {
       if (Clon->sk==0) {
          #ifdef _Secure_application_server
          if (Clon==Lstclon.Cl) continue;
          #endif
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
   if (Clon[1].rq=='U') k |= 2;
   if (ca>0) {
      if (k==0) continue;
      }
   else {
      if (k<=1) break;
      }
   if ((k&0x7ffe)==0x400) Othinf.req = 'Z';
   if (k%2>0) {
      if (ca>0 || (k>1)) {
         for (k=0,Clon=Lstclon.Cl; Clon->Sb; Clon++)
             if (Clon->sk>0) if (Clon->rq==0)
                k++;
         if (k>0) sigsuspend(&Othinf.omsk);
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

static int prepareAdminRequest(SRV_conn *Conn) {
char Ip[INET6_ADDRSTRLEN];
T_cloninfo *Clon;
int s,k;
k = checkAdminRequest(Conn);
if (k==404) return k;
if (k=='S') {
   nPrintf(Conn,"Ok server %s %d -show\nClone Status Socket IP address\n",Othinf.Npg,((T_cloninfo *)Conn)->pd);
   for (s=0,Clon=Lstclon.Cl; Clon->Sb; s++,Clon++)
       if (Clon->pd) if (Clon->sk) {
          s = Clon->rq ? Clon->rq : '-';
          inet_ntop(Srvinfo.af,&Clon->Co.Ipc,Ip,sizeof(Ip));
          nPrintf(Conn,"%5d    %c %7d  %s\n",Clon->pd,s,Clon->sk,Ip);
          }
   for (s=0,Clon=Lstclon.Cl; Clon->Sb; Clon++)
       if (Clon->mi>s) s = Clon->mi;
   nPrintf(Conn,"Buffer for input operations: %d octets\n",s+4);
   for (s=0,Clon=Lstclon.Cl; Clon->Sb; Clon++)
       if (Clon->mt>s) s = Clon->mt;
   nPrintf(Conn,"Buffer for temporary strings: %d octets\n",s+4);
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
          for (s=Srvcfg.stks-1; s>=0; s--)
              if (Clon->Sb[s]!=0) break;
      }
   nPrintf(Conn,"Maximum stack size: %d\n",(s+4)*sizeof(int));
   k = 'S';
   }
else {
   ((T_cloninfo *)Conn)->rq = k;
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
   #ifndef _Secure_application_server
   else
   if (hk==404) hk = prepareAdminRequest(&Clon->Co);
   #endif
   if (hk==404) nPrintf(&Clon->Co,"%s Not found\n",Srvinfo.Rh[1]);
   sendToClient(&Clon->Co,NULL,0);
   closeSocket(Clon);
   kill(Othinf.pid,SIGCONT);
   } while (1);
return Clon->pd = Clon->rq = 0;
}

#ifdef _Secure_application_server
static int secureAdminRequest(SRV_conn *Conn) {
static char *Smtx = "-ZVW--X";
stack_t Ss;
int k;
struct pollfd Pos;
Ss.ss_sp = Conn->Stk;
Ss.ss_size = Scfg.stks * sizeof(int);
sigaltstack(&Ss,NULL);
setSignal(SIGCONT,processSignal,0);
setSignal(SIGCHLD,processSignal,0);
setSignal(SIGPIPE,SIG_IGN,0);
setSignal(SIGSEGV,processSignal,SA_ONSTACK);
setSignal(SIGFPE,processSignal,0);
Conn->Bfi = Conn->Bfo = calloc(2048,1);
if (Conn->Bfi==NULL) {
   kill(Oinf.pid,SIGKILL);
   errorMessage("admin",errno);
   exit(1);
   }
Conn->Bft = Conn->Bfo + 1024;
Conn->Pct = Conn->Bft + 1;
Conn->Pet = Conn->Bft + 1024;
if (Srvinfo.af==AF_INET) Secinf.Psa = &Secinf.Sado.sin_addr.s_addr;
   else Secinf.Psa = Secinf.Sadn.sin6_addr.s6_addr;
Conn->Prm = Conn->Hdr = "";
do {
   Conn->Pco = Conn->Bfi;
   if (Oinf.snl) kill(Oinf.pid,SIGCONT);
   Conn->sts = 1;
   Pos.fd = Secinf.dsk;
   Pos.events = POLLIN;
   Pos.revents = 0;
   if (ppoll(&Pos,1,NULL,&Oinf.omsk)>0) {
      k = sizeof(Secinf.Sadn);
      k = accept(Secinf.dsk,(struct sockaddr *)Secinf.Psa,&k);
      }
   else k = -1;
   if (k<0) continue;
   if (memcmp(Secinf.Psa,Scfg.Lhst,Oinf.lsa)!=0) {
      close(k);
      k = 0;
      continue;
      }
   Conn->sck = k;
   memcpy(Conn->Ipc,Oinf.Psa,Oinf.lsa);
   memset(Conn->Bfi,0,2048);
   setsockopt(Conn->sck,SOL_SOCKET,SO_RCVTIMEO,&Scfg.Trcv,sizeof(Scfg.Trcv));
   setsockopt(Conn->sck,SOL_TCP,TCP_NODELAY,&k,sizeof(k));
   recv(Conn->sck,Conn->Bfi,1020,0);
   k = checkAdminRequest();
   if (k>0) {
      serverMutex(Conn,k);
      nPrintf(Conn,"%s, ok %s %d\n",Oinf.Npg,Cmds[strchr(Smtx,k)-Smtx],Conn->pid);
      }
   sendToClient(Conn);
   shutdown(Conn->sck,SHUT_WR);
   close(Conn->sck);
   Conn->sck = 0;
   } while (k!='Z');
return 0;
}
#endif

static void serverCycle(void) {
struct pollfd Pos;
T_cloninfo *Clon;
int *Sb, hk;
char *Ms;
setSignal(SIGCONT,processSignal,0);
setSignal(SIGCHLD,processSignal,0);
sigemptyset(&Othinf.mask);
sigaddset(&Othinf.mask,SIGCONT);
sigaddset(&Othinf.mask,SIGCHLD);
sigprocmask(SIG_BLOCK,&Othinf.mask,&Othinf.omsk);
Srvinfo.data('L');
Srvinfo.html('L');
Othinf.err = initServer();
#ifdef _Secure_application_server
/* install secure admin request procedure */
Ms = " and secure";
#else
Ms = "";
#endif
fprintf(stderr,"Server active, IPv%d release%s version\n",Srvinfo.af==AF_INET?4:6,Ms);
do {
   Pos.fd = Othinf.dsk;
   Pos.events = POLLIN;
   Pos.revents = 0;
   if (ppoll(&Pos,1,NULL,&Othinf.omsk)>0) {
      hk = sizeof(Othinf.San);
      hk = accept(Othinf.dsk,(struct sockaddr *)&Othinf.San,&hk);
      }
   else hk = -1;
   if (hk>0) {
      Clon = cloneAvailable(1);
      memset(&Clon->Co,0,sizeof(SRV_conn));
      memcpy(Clon->Co.Ipc,Srvcfg.Psa,Srvcfg.lsa);
      Clon->sk = hk;
      if (Clon->pd==0) {
         Sb = Clon->Sb + Srvcfg.stkT;
         Clon->pd = clone((int (*)(void *))userRequest,Sb,CLONE_FS|CLONE_FILES|CLONE_VM|SIGCHLD,Clon);
         }
      else kill(Clon->pd,SIGCONT);
      continue;
      }
   else cloneAvailable(0);
   } while (Othinf.req!='Z');
for (Clon=Lstclon.Cl; Clon->Sb; Clon++)
    kill(Clon->pd,SIGCONT);
kill(Clon[1].pd,SIGCONT);
}

#else

static void serverCycle(void) {
T_cloninfo *Clon;
int hk;
Srvinfo.data('L');
Srvinfo.html('L');
setSignal(SIGALRM,processSignal,0);
setSignal(SIGCONT,processSignal,0);
setSignal(SIGCHLD,processSignal,0);
initServer();
fprintf(stderr,"Server active, IPv%d debug version\n",Srvinfo.af==AF_INET?4:6);
Clon = Lstclon.Cl;
do {
   hk = sizeof(Othinf.San);
   hk = accept(Othinf.dsk,(struct sockaddr *)&Othinf.San,&hk);
   if (hk<0) continue;
   memset(Clon,0,sizeof(SRV_conn));
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
                case 'D': Srvinfo.data('R');
                          Srvinfo.data('L');
                          break;
                case 'H': Srvinfo.html('R');
                          Srvinfo.html('L');
                          break;
                case 'S': nPrintf(&Clon->Co,"Buffer for input operations: %d octets\n",Clon->mi+4);
                          nPrintf(&Clon->Co,"Buffer for temporary strings: %d octets\n",Clon->mt+4);
                          break;
                }
         nPrintf(&Clon->Co,"Ok server %s %d (debug version) %s\n",Othinf.Npg,Othinf.pid,whichCommand(hk));
         }
      if (hk=='W') {
         recv(Clon->sk,Clon->Bf,1020,0);
         if (memcmp(Clon->Bf,"Ok data",7)==0) {
            Srvinfo.data('R');
            Srvinfo.data('L');
            }
         }
      if (hk==404) nPrintf(&Clon->Co,"%s Not found\n",Srvinfo.Rh[1]);
      }
   sendToClient(&Clon->Co,NULL,0);
   close(Clon->sk);
   } while (hk!='Z');
}

#endif

static void dummyLoadFree(char op) { }

int main(int agc, char **Agv) {
int o;
Srvinfo.Nv = "";
Srvinfo.data = Srvinfo.html = dummyLoadFree;
registerUserSettings();
if (Srvinfo.preq==NULL) {
   fputs("Process request (Srvinfo.prq) not defined\n",stderr);
   exit(1);
   }
Othinf.pid = getpid();
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
   #ifdef _Secure_application_server
   SSL_load_error_strings();
   OpenSSL_add_all_algorithms();
   Secinf.Mtd = SSLv23_server_method();
   #endif
   if (Srvinfo.ss>0) {
      sprintf(Othinf.Buf,"%s.ssn",Srvcfg.Npg);
      initSessions(Othinf.Buf);
      }
   Srvcfg.stkT = Srvcfg.stks; /* drop this line if stack is growing upward */
   serverCycle();
   }
else processCommand(Cmds[o]);
return 0;
}
