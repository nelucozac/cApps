/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

typedef struct { int p; char *W; } INF_word;

static struct { 
       INF_word *Wrd;
       int nwo, mlw, mld, dfh, mtx;
       char *Bfi, *Htm;
       } Dic_inf;

typedef struct { char *W, *D; } USR_info;

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

static int cmpW(const void *A, const void *B) {
INF_word *P, *Q;
int d;
P = (INF_word *)A;
Q = (INF_word *)B;
if (d=strcmp(P->W,Q->W)) return d;
return P->p - Q->p;
}

static void loadUserData(void) {
char *Inp,*Out;
int k,l;
INF_word *Pinfw;
Dic_inf.Bfi = Inp = Out = loadTextFile("Dictio.idx");
Inp = myScanf(Inp,"dd",&Dic_inf.nwo,&Dic_inf.mld);
Dic_inf.Wrd = calloc(Dic_inf.nwo+1,sizeof(INF_word));
Dic_inf.mlw = 0;
for (k=0,Pinfw=Dic_inf.Wrd; k<Dic_inf.nwo; k++,Pinfw++) {
    Pinfw->W = Out;
    Inp = myScanf(Inp,"ds",&Pinfw->p,Out);
    l = strlen(Out);
    if (Dic_inf.mlw<l) Dic_inf.mlw = l;
    Out += l + 1;
    }
qsort(Dic_inf.Wrd,Dic_inf.nwo,sizeof(INF_word),cmpW);
Dic_inf.Wrd[Dic_inf.nwo].W = "~";
Dic_inf.dfh = open("Dictio.dat",O_RDWR);
}

static void freeUserData(void) {
free(Dic_inf.Bfi);
free(Dic_inf.Wrd);
close(Dic_inf.dfh);
}

static void manageUserData(char op) {
if (op=='L') loadUserData();
   else freeUserData();
}

static void manageUserHtml(char op) {
if (op=='L') Dic_inf.Htm = loadTextFile("Dictio.htm");
   else free(Dic_inf.Htm);
}

static INF_word *wordSearch(char *Wrd, int ls) {
int l,r,m,d;
INF_word *Pinfw;
l = 0;
r = Dic_inf.nwo - 1;
do {
   m = (l + r) / 2;
   Pinfw = Dic_inf.Wrd + m;
   d = memcmp(Pinfw->W,Wrd,ls);
   if (d==0) {
      if (m>0) if (memcmp((Pinfw-1)->W,Wrd,ls)==0) d++;
      if (d==0) return Pinfw;
      }
   if (d<0) l = m + 1;
      else r = m - 1;
   } while (l<=r);
return NULL;
}

static void displayHelp(SRV_conn *Conn) {
char *Wrd,*Pvw;
int lw,k;
INF_word *Pinfw;
Wrd = ((USR_info *)Conn->Usr)->W;
if (*Wrd) do {
   lw = strlen(Wrd);
   k = 0;
   Pinfw = wordSearch(Wrd,lw);
   if (Pinfw==NULL) break;
   Pvw = "";
   while (k<10) {
         if (strcmp(Pinfw->W,Pvw)!=0) {
            nPrintf(Conn,"%s\n",Pinfw->W);
            Pvw = Pinfw->W;
            k++;
            }
         Pinfw++;
         if (memcmp(Pinfw->W,Wrd,lw)!=0) break;
         }
   } while (0);
}

static void displayDefs(SRV_conn *Conn) {
char *Fmt,*Wrd,*Def,*P;
INF_word *Pinfw;
int l;
Wrd = ((USR_info *)Conn->Usr)->W;
nPrintf(Conn,Dic_inf.Htm,Wrd);
Fmt = endOfString(Dic_inf.Htm,1);
Def = ((USR_info *)Conn->Usr)->D;
if (*Wrd) do {
   Pinfw = wordSearch(Wrd,strlen(Wrd)+1);
   if (Pinfw==NULL) break;
   Fmt = endOfString(Dic_inf.Htm,1);
   do {
      serverMutex(Conn,&Dic_inf.mtx,'L');
      lseek(Dic_inf.dfh,Pinfw->p,SEEK_SET);
      l = read(Dic_inf.dfh,Def,Dic_inf.mld);
      serverMutex(Conn,&Dic_inf.mtx,'R');
      if (P=strchr(Def,'\n')) *P = 0;
      Def[l] = 0;
      nPrintf(Conn,Fmt,Wrd,Def);
      Pinfw++;
      } while (strcmp(Pinfw->W,Wrd)==0);
   } while (0);
Fmt = endOfString(Fmt,1);
nPrintf(Conn,Fmt,getTime(NULL)-Conn->tim);
}

static void strCopy(char *Ds, char *So, int ls) {
char c;
int k;
k = 0;
while (c=*So++) if (isalpha(c)) {
      *Ds++ = tolower(c);
      if (++k==ls) break;
      }
*Ds = 0;
}

static void processRequest(SRV_conn *Conn) {
char *P;
int l;
USR_info Prms;
Conn->Usr = &Prms;
P = getLastParamValue(Conn,"W");
l = strlen(P);
if (l>Dic_inf.mlw) l = Dic_inf.mlw;
Prms.W = Conn->Pet - l - 3;
strCopy(Prms.W,P,l);
Conn->Pet = Prms.D = Prms.W - Dic_inf.mld - 3;
P = getLastParamValue(Conn,"O");
if (*P=='H') displayHelp(Conn);
   else displayDefs(Conn);
}

void registerUserSettings(void) {
Srvinfo.preq = processRequest;
Srvinfo.data = manageUserData;
Srvinfo.html = manageUserHtml;
Dic_inf.mtx = 1;
}
