/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

typedef struct { int p; char *W; } T_wordinf;

static struct { 
       T_wordinf *Wrd;
       int nwo, mlw, mld, dfh;
       char *Bfi, *Htm;
       pthread_mutex_t mtx;
       } Dic_inf;

typedef struct { char *W, *D; } T_userinf;

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
T_wordinf *P, *Q;
int d;
P = (T_wordinf *)A;
Q = (T_wordinf *)B;
if (d=strcmp(P->W,Q->W)) return d;
return P->p - Q->p;
}

static void loadUserData(void) {
char *Inp,*Out;
int k,l;
T_wordinf *Pinfw;
Dic_inf.Bfi = Inp = Out = CAS_loadTextFile("Dictio.idx");
Inp = myScanf(Inp,"dd",&Dic_inf.nwo,&Dic_inf.mld);
Dic_inf.Wrd = calloc(Dic_inf.nwo+1,sizeof(T_wordinf));
Dic_inf.mlw = 0;
for (k=0,Pinfw=Dic_inf.Wrd; k<Dic_inf.nwo; k++,Pinfw++) {
    Pinfw->W = Out;
    Inp = myScanf(Inp,"ds",&Pinfw->p,Out);
    l = strlen(Out);
    if (Dic_inf.mlw<l) Dic_inf.mlw = l;
    Out += l + 1;
    }
qsort(Dic_inf.Wrd,Dic_inf.nwo,sizeof(T_wordinf),cmpW);
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
if (op=='L') Dic_inf.Htm = CAS_loadTextFile("Dictio.htm");
   else free(Dic_inf.Htm);
}

static T_wordinf *wordSearch(char *Wrd, int ls) {
int l,r,m,d;
T_wordinf *Pinfw;
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

static void displayHelp(CAS_srvconn_t *Conn) {
char *Wrd,*Pvw;
int lw,k;
T_wordinf *Pinfw;
Wrd = ((T_userinf *)Conn->Usr)->W;
if (*Wrd) do {
   lw = strlen(Wrd);
   k = 0;
   Pinfw = wordSearch(Wrd,lw);
   if (Pinfw==NULL) break;
   Pvw = "";
   while (k<10) {
         if (strcmp(Pinfw->W,Pvw)!=0) {
            CAS_nPrintf(Conn,"%s\n",Pinfw->W);
            Pvw = Pinfw->W;
            k++;
            }
         Pinfw++;
         if (memcmp(Pinfw->W,Wrd,lw)!=0) break;
         }
   } while (0);
}

static void displayDefs(CAS_srvconn_t *Conn) {
char *Fmt,*Wrd,*Def,*P;
T_wordinf *Pinfw;
int l;
Wrd = ((T_userinf *)Conn->Usr)->W;
CAS_nPrintf(Conn,Dic_inf.Htm,Wrd);
Fmt = CAS_endOfString(Dic_inf.Htm,1);
Def = ((T_userinf *)Conn->Usr)->D;
if (*Wrd) do {
   Pinfw = wordSearch(Wrd,strlen(Wrd)+1);
   if (Pinfw==NULL) break;
   Fmt = CAS_endOfString(Dic_inf.Htm,1);
   do {
      pthread_mutex_lock(&Dic_inf.mtx);
      lseek(Dic_inf.dfh,Pinfw->p,SEEK_SET);
      l = read(Dic_inf.dfh,Def,Dic_inf.mld);
      pthread_mutex_unlock(&Dic_inf.mtx);
      if (P=strchr(Def,'\n')) *P = 0;
      Def[l] = 0;
      CAS_nPrintf(Conn,Fmt,Wrd,Def);
      Pinfw++;
      } while (strcmp(Pinfw->W,Wrd)==0);
   } while (0);
Fmt = CAS_endOfString(Fmt,1);
CAS_nPrintf(Conn,Fmt,CAS_getTime(Conn));
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

static void processRequest(CAS_srvconn_t *Conn) {
char *P;
int l;
T_userinf Prms;
Conn->Usr = &Prms;
P = CAS_getLastParamValue(Conn,"W");
l = strlen(P);
if (l>Dic_inf.mlw) l = Dic_inf.mlw;
Prms.W = Conn->Pet - l - 3;
strCopy(Prms.W,P,l);
Conn->Pet = Prms.D = Prms.W - Dic_inf.mld - 3;
P = CAS_getLastParamValue(Conn,"O");
if (*P=='H') displayHelp(Conn);
   else displayDefs(Conn);
}

void CAS_registerUserSettings(void) {
CAS_Srvinfo.preq = processRequest;
CAS_Srvinfo.data = manageUserData;
CAS_Srvinfo.html = manageUserHtml;
pthread_mutex_init(&Dic_inf.mtx,NULL);
}
