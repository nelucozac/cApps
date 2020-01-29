/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "datsG.h"
#include <limits.h>

#define Infinity (INT_MAX/2)

INF_graph Graph;

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
   if (c=='c') {
      Pch = va_arg(Prms,char *);
      *Pch = *Bfi++;
      continue;
      }
   if (c=='S') {
      Pch = va_arg(Prms,char *);
      do {
         c = *Bfi++;
         if (c==0) break;
         if (iscntrl(c)) break;
         *Pch++ = c;
         } while (1);
      *Pch = 0;
      continue;
      }
   } while (1);
va_end(Prms);
return Bfi;
}

static int cmpN(const void *A, const void *B) {
INF_node **P, **Q;
P = (INF_node **)A;
Q = (INF_node **)B;
return strcasecmp(P[0]->N+1,Q[0]->N+1);
}

static void loadUserData(void) {
char *Inp,*Out,*Lnk,*P;
int k,l,x,y,c;
INF_succ *Ps;
static INF_node Fnod;
Graph.ml = 0;
Inp = Out = loadTextFile("Graph.nod");
Inp = myScanf(Inp,"d",&Graph.nn);
Graph.In = calloc(Graph.nn+1,sizeof(INF_node));
Graph.Ia = calloc(Graph.nn+1,sizeof(INF_node *));
Graph.In[0].N = Out;
Graph.Sc = calloc(Graph.nn+2,sizeof(INF_succ **));
for (k=0; k<Graph.nn; k++) {
    Inp = myScanf(Inp,"dcS",&x,Out,Out+1);
    Graph.In[x].k = x;
    Graph.In[x].N = Out;
    Graph.Ia[k] = Graph.In + x;
    l = strlen(Out);
    Out += l + 1;
    if (Graph.ml<l) Graph.ml = l;
    }
qsort(Graph.Ia,Graph.nn,sizeof(INF_node *),cmpN);
Graph.Ia[Graph.nn] = &Fnod;
Fnod.N = "";
Lnk = loadTextFile("Graph.lnk");
P = myScanf(Lnk,"d",&k);
Graph.Sc[0] = Ps = calloc(k+1,sizeof(INF_succ));
do {
   x = -1;
   P = myScanf(P,"dd",&x,&k);
   if (x<0) break;
   Graph.Sc[x] = Ps;
   for (l=0; l<k; l++) {
       P = myScanf(P,"dd",&y,&c);
       Ps->s = y; Ps->c = c;
       Ps++;
       }
   } while (1);
Graph.Sc[Graph.nn] = Ps;
free(Lnk);
}

static int extractFromQueue(VMARK *Mk) {
int x,y,k,l,w,c,*Q;
for (k=0,Q=Mk->Q,c=Infinity; k<Mk->n; k++) {
    y = *Q++;
    w = Mk->C[y];
    if (w<c) {
       x = y;
       c = w;
       l = k;
       }
    }
Mk->Q[l] = Mk->Q[--Mk->n];
Mk->E[x]++;
return x;
}

static int modifyCost(VMARK *Mk, int y, int w) {
if (Mk->C[y]<=w) return 0;
Mk->C[y] = w;
if (Mk->E[y]<0) {
   Mk->Q[Mk->n++] = y;
   Mk->E[y]++;
   }
return 1;
}

void minCostPath(int dep, int arv, VMARK *Mk) {
int x,y,w,*C;
INF_succ *Ps,*Pn;
Mk->C = calloc(Graph.nn+1,sizeof(int));
Mk->P = calloc(Graph.nn+1,sizeof(int));
Mk->Q = calloc(Graph.nn+1,sizeof(int));
Mk->E = calloc(Graph.nn+1,sizeof(signed char));
for (x=1,C=Mk->C+1; x<=Graph.nn; x++)
    *C++ = Infinity;
memset(Mk->E,-1,Graph.nn+1);
Mk->n = x = 0;
modifyCost(Mk,dep,0);
while (Mk->n>0) {
      x = extractFromQueue(Mk);
      if (x==arv) break;
      for (Ps=Graph.Sc[x],Pn=Graph.Sc[x+1]; Ps<Pn; Ps++) {
          y = Ps->s;
          if (Mk->E[y]>0) continue;
          w = Mk->C[x] + Ps->c;
          if (modifyCost(Mk,y,w)) Mk->P[y] = x;
          }
      }
if (x==arv) {
   Mk->Q[Mk->n=0] = x;
   while (x!=dep) {
         x = Mk->P[x];
         Mk->Q[++Mk->n] = x;
         }
   }
else Mk->n = -1;
free(Mk->P);
free(Mk->E);
}

static void freeUserData(void) {
free(Graph.In[0].N);
free(Graph.In);
free(Graph.Ia);
free(Graph.Sc[0]);
free(Graph.Sc);
}

void manageUserData(char op) {
if (op=='L') loadUserData();
   else freeUserData();
}
