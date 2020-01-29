/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "datsG.h"

typedef struct { char *Fh, *D, *A; } USER_info;

static USER_info Fran, Engl;

static void manageUserHtml(char op) {
if (op=='L') {
   Fran.Fh = loadTextFile("Fgraph.htm");
   Engl.Fh = loadTextFile("Egraph.htm");
   }
else {
   free(Fran.Fh);
   free(Engl.Fh);
   }
}

static INF_node **nodeSearch(char *Nod, int ls) {
int l,r,m,d;
INF_node **Pn;
l = 0;
r = Graph.nn - 1;
do {
   m = (l + r) / 2;
   Pn = Graph.Ia + m;
   d = strncasecmp(Pn[0]->N+1,Nod,ls);
   if (d==0) {
      if (m>0) if (strncasecmp(Graph.Ia[m-1]->N+1,Nod,ls)==0) d++;
      if (d==0) return Pn;
      }
   if (d<0) l = m + 1;
      else r = m - 1;
   } while (l<=r);
return NULL;
}

static void displayHelp(SRV_conn *Conn) {
char *Pvn,*P;
int lw,k;
INF_node **Pnm;
USER_info *Prms;
Prms = Conn->Usr;
if (*Prms->D) do {
   lw = strlen(Prms->D);
   k = 0;
   Pnm = nodeSearch(Prms->D,lw);
   if (Pnm==NULL) break;
   Pvn = "";
   while (k<10) {
         P = Pnm[0]->N + 1;
         if (strcasecmp(P,Pvn)!=0) {
            nPrintf(Conn,"%s\n",P-1);
            Pvn = P;
            k++;
            }
         Pnm++;
         if (strncasecmp(Pnm[0]->N+1,Prms->D,lw)!=0) break;
         }
   } while (0);
}

static void displayRoute(SRV_conn *Conn) {
char *Fmt,*P;
int dep,arv,lw,tp,s,nv;
INF_node **Pnm;
VMARK Mk;
USER_info *Prms;
Prms = Conn->Usr;
dep = arv = 0;
if (*Prms->D) {
   lw = strlen(Prms->D);
   if (Pnm=nodeSearch(Prms->D,lw)) dep = Pnm[0]->k;
   }
if (*Prms->A) {
   lw = strlen(Prms->A);
   if (Pnm=nodeSearch(Prms->A,lw)) arv = Pnm[0]->k;
   }
nPrintf(Conn,Prms->Fh,Prms->D,Prms->A);
Fmt = endOfString(Prms->Fh,1);
memset(&Mk,0,sizeof(Mk));
Mk.n = -1;
tp = 0;
P = getLastParamValue(Conn,"Dsp");
if (dep>0) if (arv>0) if (dep!=arv) {
   minCostPath(dep,arv,&Mk);
   nPrintf(Conn,Fmt,getTime(NULL)-Conn->tim);
   if (*P) tp = strlen(Prms->Fh);
   }
Fmt = endOfString(Fmt,1);
s = strlen(Fmt);
nv = Mk.n + 1;
while (Mk.n>=0) {
   dep = Mk.Q[Mk.n--];
   Prms->D = Graph.In[dep].N;
   lw = Prms->D[0] == '1' ? 800 : 400;
   tp += strlen(Prms->D) + s;
   if (*P) nPrintf(Conn,Fmt,Mk.C[dep],lw,Prms->D+1);
   }
Fmt = endOfString(Fmt,1);
if (tp>0) if (*P==0) {
   tp = (tp + 1023) / 1024;
   nPrintf(Conn,Fmt,nv,Mk.C[arv],tp);
   }
Fmt = endOfString(Fmt,1);
nPrintf(Conn,Fmt,getTime(NULL)-Conn->tim);
}

static void strCopy(char *Tg, char *So) {
char *P,*Q,c;
P = So;
Q = Tg;
while (c=*P++) if (!isspace(c) || (Q>Tg)) {
      if (isspace(c)) if (isspace(*(Q-1)))
         continue;
      *Q = isalpha(c) ? tolower(c) : c;
      Q++;
      }
if (Q>Tg) {
   Q--;
   do {
      if (isspace(*Q)) Q--;
         else break;
      } while (1);
   }
Q[1] = 0;
}

static void processRequest(SRV_conn *Conn) {
char *Str;
USER_info Prms;
int l;
Str = getLastParamValue(Conn,"Lng");
Conn->Usr = &Prms;
if (*Str=='E') memcpy(&Prms,&Engl,sizeof(USER_info));
   else memcpy(&Prms,&Fran,sizeof(USER_info));
Str = getLastParamValue(Conn,"Dep");
l = strlen(Str) + 2;
Prms.D = Conn->Pet - l;
strCopy(Prms.D,Str);
Str = getLastParamValue(Conn,"Arv");
l += strlen(Str) + 2;
Prms.A = Prms.D - l;
strCopy(Prms.A,Str);
Str = getLastParamValue(Conn,"Sub");
if (*Str=='H') displayHelp(Conn);
   else displayRoute(Conn);
}

void registerUserSettings() {
Srvinfo.preq = processRequest;
Srvinfo.data = manageUserData;
Srvinfo.html = manageUserHtml;
}
