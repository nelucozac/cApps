/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"
#include <pthread.h>

#define NREQS 10000
#define BFSIZE 16384

typedef struct {
        pthread_t p;
        int s;
        union { struct sockaddr_in O; struct sockaddr_in6 N; } ;
        char *B;
        } PTHR_inf;

static PTHR_inf *Lthr;

static char **Dictio, Ipa[16], Ips[48];

static int nwords, nthrs, port, ipv, nrt;

static char *myScanf(char *Bfi, char *Fmt, ...) {
va_list Prms;
char *Pch,c;
int *Pint,val;
va_start(Prms,Fmt);
do {
   c = *Fmt++;
   if (c==0) break;
   while (isspace(*Bfi)) Bfi++;
   if (*Bfi==0) return NULL;
   if (c=='d') {
      Pint = va_arg(Prms,int *);
      val = 0;
      do {
         c = *Bfi++;
         if (isdigit(c)==0) break;
         val = val * 10 + c - '0';
         } while (1);
      *Pint = val;
      continue;
      }
   if (c=='s') {
      Pch = va_arg(Prms,char *);
      do {
         c = *Bfi++;
         if (c==0) break;
         if (isspace(c)) break;
         *Pch++ = c;
         } while (1);
      *Pch = 0;
      continue;
      }
   } while (1);
va_end(Prms);
return Bfi;
}

static void readDictio(void) {
int k,l;
char *Bf,*P;
k = open("Dictio.idx",O_RDONLY);
l = lseek(k,0,SEEK_END);
lseek(k,0,SEEK_SET);
Bf = calloc(l+1,1);
l = read(k,Bf,l);
close(k);
P = myScanf(Bf,"dd",&nwords,&l);
if (nwords<NREQS) nwords = NREQS;
Dictio = calloc(nwords+1,sizeof(char *));
for (k=0; k<nwords; k++) {
    Dictio[k] = Bf;
    P = myScanf(P,"ds",&l,Bf);
    Bf = CAS_endOfString(Bf,1);
    if (*P==0) break;
    }
for (; k<nwords; k++) Dictio[k] = "zzzzzzz";
}

static void benchMarkConfig(void) {
int k;
PTHR_inf *Pt;
fputs("Benchmark - online dictionary server\n",stderr);
fputs("How much threads (between 1 and 25) ? ",stderr);
k = scanf("%d",&nthrs);
if (nthrs<=0) nthrs = 1;
if (nthrs>25) nthrs = 25;
while (NREQS%nthrs>0) nthrs++;
fprintf(stderr,"Number of threads: %d\n",nthrs);
fputs("Enter the Ip version (4 or 6) : ",stderr);
k = scanf("%d",&ipv);
ipv = ipv == 4 ? AF_INET : AF_INET6;
fputs("Ip version 4, local host 127.0.0.1\nIp version 6, local host ::1\n",stderr);
fputs("Enter the Ip address of server: ",stderr);
k = scanf("%s",Ips);
inet_pton(ipv,Ips,Ipa);
fputs("Enter the port number: ",stderr);
k = scanf("%d",&port);
Lthr = calloc(nthrs+1,sizeof(PTHR_inf));
for (k=0,Pt=Lthr; k<nthrs; k++,Pt++)
    Pt->B = malloc(BFSIZE);
nrt = NREQS / nthrs;
}

static void checkResponse(char *Bi) {
if (strstr(Bi,"</html>")==NULL) {
   fputs("Some errors occured\n",stderr);
   exit(1);
   }
}

static void *process(PTHR_inf *Arg) {
int r,k;
char **Pdi,**Pdf,**Pd,*B;
Pdi = Dictio + (Arg-Lthr) * nrt;
Pdf = Pdi + nrt;
if (ipv==AF_INET) {
   Arg->O.sin_family = ipv;
   Arg->O.sin_port = htons(port);
   memcpy(&Arg->O.sin_addr.s_addr,Ipa,4);
   }
else {
   Arg->N.sin6_family = ipv;
   Arg->N.sin6_port = htons(port);
   memcpy(Arg->N.sin6_addr.s6_addr,Ipa,16);
   }
for (Pd=Pdi; Pd<Pdf; Pd++) {
    Arg->s = socket(ipv,SOCK_STREAM,IPPROTO_TCP);
    while (connect(Arg->s,(struct sockaddr *)&Arg->N,sizeof(Arg->N))<0)
          if (errno==ECONNREFUSED) {
             perror("connect");
             exit(1);
             }
    sprintf(Arg->B,"GET /?W=%s HTTP/1.1\n",*Pd);
    send(Arg->s,Arg->B,strlen(Arg->B),0);
    B = Arg->B;
    memset(B,0,BFSIZE);
    do {
       k = BFSIZE - (B - Arg->B) - 1;
       r = recv(Arg->s,B,k,0);
       B += r; /* drop this line if you don't know maximum size of html page */
       } while (r==k);
    checkResponse(Arg->B);
    close(Arg->s);
    }
return NULL;
}

int main() {
struct timeval Tma,Tmb;
long double ti;
PTHR_inf *Pt;
readDictio();
benchMarkConfig();
gettimeofday(&Tma,NULL);
for (Pt=Lthr; Pt->B; Pt++)
    pthread_create(&Pt->p,NULL,(void *(*)(void *))process,Pt);
for (Pt=Lthr; Pt->B; Pt++) pthread_join(Pt->p,NULL);
gettimeofday(&Tmb,NULL);
ti = ((long double)Tmb.tv_sec - Tma.tv_sec) + ((long double)Tmb.tv_usec - Tma.tv_usec) / 1000000.0;
free(Dictio[0]);
free(Dictio);
fprintf(stderr,"Elapsed time: %.5Lf seconds\n",ti);
fprintf(stderr,"Time per request (average): %.5Lf seconds\n",ti/NREQS);
fprintf(stderr,"Requests per second (average): %.5Lf requests\n",NREQS/ti);
return 0;
}
