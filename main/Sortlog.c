#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef struct {
        char *Pr, *Pa, *Pe, *Pp;
        int k;
        } T_analyse;

static T_analyse *Elog;
static int nelg, lfil;

static void readErrorLog(char *Fne) {
T_analyse *Pel;
char *Buf,*P,*Q;
int fh,k;
fh = open(Fne,O_RDONLY);
if (fh<0) {
   perror("Open log file");
   exit(1);
   }
lfil = lseek(fh,0,SEEK_END);
lseek(fh,0,SEEK_SET);
Buf = calloc(lfil+1,1);
if (Buf==NULL) {
   perror("Alloc log file");
   exit(1);
   }
k = read(fh,Buf,lfil);
close(fh);
nelg = 0;
P = Buf;
do {
   if (*P==0) break;
   if (isdigit(*P)) nelg++;
   if (P=strchr(P,'\n')) *P++;
   } while (1);
if (nelg==0) {
   fputs("Empty error log file, nothing to do\n",stderr);
   exit(1);
   }
Elog = Pel = calloc(nelg+1,sizeof(T_analyse));
P = Buf;
k = 0;
do {
   if (Q=strchr(P,'\n')) *Q++ = 0;
   if (isdigit(*P)) {
      Pel->Pr = P;
      P = strchr(P,' ') + 1;
      P = strchr(P,' ') + 1;
      Pel->Pa = P;
      Pel->Pe = strchr(P,' ') + 1;
      Pel->k = k++;
      Pel++;
      }
   else Pel->Pp = P;
   P = Q;
   } while (P && *P);
}

static int cmpA(const void *A, const void *B) {
T_analyse *Pa = (T_analyse *)A, *Pb = (T_analyse *)B;
char *P;
int d;
if (d=strcmp(Pa->Pe,Pb->Pe)) return d;
P = strchr(Pa->Pa,' ');
if (d=memcmp(Pa->Pa,Pb->Pa,P-Pa->Pa)) return d;
return Pa->k -Pb->k;
}

static int cmpB(const void *A, const void *B) {
T_analyse *Pa = (T_analyse *)A, *Pb = (T_analyse *)B;
char *P,*Q;
int d;
if (d=strcmp(Pa->Pe,Pb->Pe)) return d;
P = strchr(Pa->Pa,' ');
return memcmp(Pa->Pa,Pb->Pa,P-Pa->Pa);
}

static void writeErrorLog(char *Fni, char *Fno) {
T_analyse *Pel,*Ppr;
char *Buf,*P;
int fh,k;
fh = open(Fno,O_WRONLY|O_CREAT,0600);
if (fh<0) {
   perror("Create output file");
   exit(1);
   }
if (Fni) if (truncate(Fni,0)<0)
   perror("Truncate");
qsort(Elog,nelg,sizeof(T_analyse),cmpA);
Buf = P = calloc(lfil+nelg,1);
for (k=0,Pel=Ppr=Elog; k<nelg; k++,Pel++) {
    if (cmpB(Pel,Ppr)!=0) {
       Ppr = Pel;
       *P++ = '\n';
       }
    P += sprintf(P,"%s\n",Pel->Pr);
    if (Pel->Pp) P += sprintf(P,"%s\n",Pel->Pp);
    }
k = write(fh,Buf,strlen(Buf));
close(fh);
fputs("Report created\n",stderr);
}

int main(int agc, char **Agv) {
int err;
fputs("Sort (for further analysis) the content of error log file\n",stderr);
fputs("The first argument: -k (keep input file) or -t (truncate after read)\n",stderr);
fputs("The second argument: error log filename\n",stderr);
fputs("The third argument: output filename\n",stderr);
fputs("The two filenames must be different\n\n",stderr);
err = 0;
if (agc!=4) err++;
if (agc>=2)
   if (strcmp(Agv[1],"-k")!=0) if (strcmp(Agv[1],"-t")!=0)
      err++;
if (agc>=4)
   if (strcmp(Agv[2],Agv[3])==0) err++;
if (err>0) {
   fputs("\nWrong command line arguments\n",stderr);
   return 1;
   }
readErrorLog(Agv[2]);
if (Agv[1][1]=='k') Agv[2] = NULL;
writeErrorLog(Agv[2],Agv[3]);
return 0;
}
