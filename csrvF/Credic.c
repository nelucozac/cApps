/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

static int minLenWrd, maxLenWrd;

static char *Td = "Temp.dat", *Ti = "Temp.idx";

static int genWord(char *Word) {
int l,j;
l = rand() % (maxLenWrd - minLenWrd + 1) + minLenWrd;
Word[l] = 0;
for (j=0; j<l; j++) Word[j] = rand() % 26 + 'a';
return l;
}

static void firstUpdatePhase(void) {
FILE *Fdef,*Fidx;
int i,l,lDef,numWrds,minLenDef,maxLenDef;
char *Word,*Defw,*P;
srand(time(NULL));
fputs("Create random dictionary\n",stderr);
fputs("Number of words: ",stderr);
l = scanf("%d",&numWrds);
fputs("Minimum and maximum length of words: ",stderr);
l = scanf("%d %d",&minLenWrd,&maxLenWrd);
fputs("Minimum and maximum length of definitions: ",stderr);
l = scanf("%d %d",&minLenDef,&maxLenDef);
Fdef = fopen(Td,"w"); Fidx = fopen(Ti,"w");
Word = calloc(maxLenWrd+1,1);
Defw = calloc(maxLenDef+maxLenWrd+2,1);
fprintf(Fidx,"%d %d\n",numWrds,maxLenDef);
for (i=0; i<numWrds; i++) {
    genWord(Word);
    fprintf(Fidx,"%ld %s\n",ftell(Fdef),Word);
    lDef = rand() % (maxLenDef - minLenDef + 1) + minLenDef;
    P = Defw;
    do {
       l = genWord(P);
       P += l;
       if (P-Defw>=lDef) {
          P = strrchr(Defw,' ');
          *P = 0;
          fprintf(Fdef,"%s\n",Defw);
          break;
          }
       *P++ = ' ';
       } while (1);
    }
fclose(Fdef); fclose(Fidx);
}

static void secondUpdatePhase(void) {
rename(Td,"Dictio.dat");
rename(Ti,"Dictio.idx");
}

static char *Mssg;
static int contactServer(char *Ncfg) {
int Fc,p,v,fs,t;
char Pswd[2044],Ipa[48],*P;
time_t ti;
union { struct sockaddr_in v4; struct sockaddr_in6 v6; } Sadr;
Fc = open(Ncfg,O_RDONLY);
if (Fc<0) return 0;
fs = lseek(Fc,0,SEEK_END);
Mssg = calloc(fs+1,1);
lseek(Fc,0,SEEK_SET);
fs = read(Fc,Mssg,fs);
close(Fc);
memcpy(Mssg,"-wait ",6);
P = strstr(Mssg,"- Server ");
P = strchr(P,'\n');
sscanf(P,"%s %d %*s %s %d %*s %*s %*s %*s %*s %*s %d",Pswd,&v,Ipa,&p,&t);
strcpy(Mssg+6,Pswd);
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
