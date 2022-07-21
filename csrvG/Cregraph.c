/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
 Create random graph and update the server
*/

#include "cAppserver.h"

#define MAXN 456976

typedef struct { int i, j, t; } T_net;
static T_net *Net, *Pn;

static int nNods, nArcs, maxLnam, nnE;

static char *Tnod = "Temp.nod", *Tlnk = "Temp.lnk", *Nnod;

static FILE *Fo;

static void genName(int k) {
int l,j;
for (j=0; j<7; j+=2) {
    Nnod[j] = rand() % 26 + 'a';
    l = k % 26; Nnod[j+1] = l + 'a';
    k /= 26;
    }
Nnod[0] = toupper(Nnod[0]);
l = rand() % (maxLnam - 7) + 8;
Nnod[l] = 0;
for (j=8; j<l; j++) Nnod[j] = rand() % 26 + 'a';
l /= 2;
if (l<8) if (l%2>0) l--;
Nnod[l++] = ' ';
Nnod[l] = toupper(Nnod[l]);
}

static void genNodes(void) {
int i,j,ns,nn;
do {
   fputs("Create random graph\nNumber of squares per edge of net (min 2): ",stderr);
   i = scanf("%d",&ns);
   fputs("Number of nodes per inner square (min 3): ",stderr);
   i = scanf("%d",&nn);
   nn--;
   nnE = ns * nn + 1;
   nNods = nnE * nnE - (nn - 1) * (nn - 1) * ns * ns;
   if (nNods>MAXN) {
      fprintf(stderr,"Graph has %d nodes > %d (maximum allowed)\n",nNods,MAXN);
      continue;
      }
   break;
   } while (1);
nArcs = (nnE - 1) * (ns + 1) * 4;
Net = Pn = calloc(nNods+1,sizeof(T_net));
for (i=0; i<nnE; i++) for (j=0; j<nnE; j++)
    if ((i%nn==0) || (j%nn==0)) {
       Pn++;
       Pn->i = i;
       Pn->j = j;
       }
}

static int cmpK(const void *A, const void *B) {
T_net *P = (T_net *)A, *Q = (T_net *)B;
int d;
if (d=P->i-Q->i) return d;
return P->j - Q->j;
}

static int checkN(int *Ln, int i, int j) {
T_net *Pw,Wn;
int k,l;
Wn.i = i; Wn.j = j;
if (Pw=bsearch(&Wn,Net+1,nNods,sizeof(T_net),cmpK)) {
   k = Pw - Net;
   for (l=0; Ln[l]; l++) ;
   Ln[l] = k;
   return 1;
   }
return 0;
}

static void genArcs(void) {
int Ln[5],k,l;
T_net *Pn;
Fo = fopen(Tlnk,"w");
fprintf(Fo,"%d\n",nArcs);
for (k=1,Pn=Net+1; k<=nNods; k++,Pn++) {
    memset(Ln,0,sizeof(Ln));
    if (Pn->i>0) checkN(Ln,Pn->i-1,Pn->j);
    if (Pn->i+1<nnE) checkN(Ln,Pn->i+1,Pn->j);
    if (Pn->j>0) checkN(Ln,Pn->i,Pn->j-1);
    if (Pn->j+1<nnE) checkN(Ln,Pn->i,Pn->j+1);
    for (l=1; Ln[l]; l++) ;
    nArcs += l;
    fprintf(Fo,"%d %d",k,l);
    if (l>2) Pn->t++;
    for (l=0; Ln[l]; l++) fprintf(Fo," %d %d",Ln[l],rand()%11+10);
    fputs("\n",Fo);
    }
fclose(Fo);
}

static void genNames(void) {
int i;
fputs("Maximum length of names: ",stderr);
i = scanf("%d",&maxLnam);
Nnod = calloc(maxLnam+1,1);
Fo = fopen(Tnod,"w");
fprintf(Fo,"%d\n",nNods);
for (i=1,Pn=Net+1; i<=nNods; i++,Pn++) {
    genName(i);
    fprintf(Fo,"%d %d %s\n",i,Pn->t,Nnod);
    }
fclose(Fo);
}

static void firstUpdatePhase(void) {
srand(time(NULL));
genNodes();
genArcs();
genNames();
}

static void secondUpdatePhase(void) {
rename(Tnod,"Graph.nod");
rename(Tlnk,"Graph.lnk");
}

static char *Mssg;
static int contactServer(char *Ncfg) {
int Fc,p,v,fs,t;
char Pswd[2004],Ipa[48],*P;
time_t ti;
union { struct sockaddr_in v4; struct sockaddr_in6 v6; } Sadr;
Fc = open(Ncfg,O_RDONLY);
if (Fc<0) return 0;
fs = lseek(Fc,0,SEEK_END);
Mssg = calloc(fs+1,1);
lseek(Fc,0,SEEK_SET);
fs = read(Fc,Mssg,fs);
close(Fc);
memcpy(Mssg,"--wait ",7);
P = strstr(Mssg,"- Server ");
P = strchr(P,'\n');
sscanf(P,"%s %d %*s %s %d %*s %*s %*s %*s %*s %*s %d",Pswd,&v,Ipa,&p,&t);
strcpy(Mssg+7,Pswd);
memset(&Sadr,0,sizeof(Sadr));
if (v==4) {
   inet_pton(AF_INET,Ipa,&Sadr.v4.sin_addr.s_addr);
   Sadr.v4.sin_family = AF_INET;
   Sadr.v4.sin_port = htons(p);
   v = AF_INET;
   }
else {
   inet_pton(AF_INET6,Ipa,&Sadr.v6.sin6_addr.s6_addr);
   Sadr.v6.sin6_family = AF_INET6;
   Sadr.v6.sin6_port = htons(p);
   v = AF_INET6;
   }
Fc = socket(v,SOCK_STREAM,IPPROTO_TCP);
ti = time(NULL);
while (connect(Fc,(struct sockaddr *)&Sadr,sizeof(Sadr))<0) {
      if (errno!=ECONNREFUSED)
         errno = time(NULL)-ti > t ? ETIMEDOUT : 0;
      if (errno!=0) return 0;
      sleep(1);
      }
send(Fc,Mssg,strlen(Mssg),0);
p = recv(Fc,Mssg,fs-1,0);
Mssg[p] = 0;
if (memcmp(Mssg,"Ok ",3)!=0) {
   fputs("Connection failed, message other than Ok\n",stderr);
   exit(1);
   }
return Fc;
}

int main(int agc, char **Agv) {
int sck;
if (agc!=2) {
   fputs("Update server, argument: server configuration file\n",stderr);
   return 0;
   }
firstUpdatePhase();
sck = contactServer(Agv[1]);
if (sck>0) {
   secondUpdatePhase();
   send(sck,"Ok data",7,0);
   close(sck);
   fputs(Mssg,stderr);
   }
else perror("Can't open configuration file");
return 0;
}
