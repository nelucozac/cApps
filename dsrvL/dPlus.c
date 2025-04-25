
#include "cAppserver.h"

typedef struct {
        char *Sva;
        time_t etm;
        int fsz;
        } T_userssn;

static char *Htmi, *Htmf;

static int maxPost;

static void userConfig(char *Cfg) {
maxPost = atoi(Cfg);
}

static void manageHtmlFiles(char op) {
if (op=='L') {
   Htmi = CAS_loadTextFile("Dplus.htm");
   Htmf = CAS_loadTextFile("Fplus.htm");
   }
else {
   free(Htmi);
   free(Htmf);
   }
}

static char *myConvertString(CAS_srvconn_t *Conn, char *Det) {
char *Buf,*Ps,c;
int s;
for (s=0,Ps=Det; c=*Ps++; ) switch (c) {
    case '\r': break;
    case '&': s += 5;
              break;
    case '\n': case '<': case '>': s += 4;
               break;
    default: s++;
             break;
    }
if (Conn) {
   if (Conn->Pct+s-2>Conn->Pet) return NULL;
      else Buf = Conn->Pct;
   }
else {
   Buf = calloc(s+1,1);
   if (Buf==NULL) return NULL;
   }
for (Ps=Buf; c=*Det++; ) switch (c) {
    case '\r': break;
    case '&': Ps += sprintf(Ps,"&amp;");
              break;
    case '\n': Ps += sprintf(Ps,"<br>");
               break;
    case '<': Ps += sprintf(Ps,"&lt;");
              break;
    case '>': Ps += sprintf(Ps,"&gt;");
              break;
    default: *Ps++ = c;
             break;
    }
*Ps++ = 0;
if (Conn) Conn->Pct = Ps;
return Buf;
}

static void processRequest(CAS_srvconn_t *Conn) {
T_userssn *Ussn;
char *Act,*Inf,*Det,*Bfi,Fnm[36];
int v,h;
Act = CAS_getLastParamValue(Conn,"Action");
CAS_checkSession(Conn);
v = Conn->Ssn != NULL && *Act;
if (v==0) {
   CAS_createSession(Conn,CAS_Srvinfo.Rh[3]);
   Ussn = Conn->Ssn;
   CAS_resetOutputBuffer(Conn);
   CAS_nPrintf(Conn,CAS_Srvinfo.Rh[3],Ussn->Sva);
   CAS_nPrintf(Conn,Htmi,maxPost,CAS_Srvinfo.fs,maxPost,CAS_Srvinfo.fs,CAS_Srvinfo.fs);
   return;
   }
Ussn = Conn->Ssn;
if (Ussn==NULL) {
   CAS_nPrintf(Conn,Htmf,"Err: session expired","","");
   return;
   }
sprintf(Fnm,"%s.tmp",Ussn->Sva);
if (Conn->Bfi[0]=='L') {
   Ussn->fsz = atoi(CAS_getLastParamValue(Conn,"fsz"));
   CAS_nPrintf(Conn,"File uploaded");
   rename(Conn->Ufn,Fnm);
   return;
   }
if (strcmp(Act,"Submit")!=0) {
   CAS_nPrintf(Conn,Htmf,"Err: unknown action","","");
   return;
   }
Inf = CAS_getLastParamValue(Conn,"Inf");
Inf = CAS_convertString(Conn,Inf,'H');
v = Ussn->fsz;
if (v>maxPost) do {
   h = open(Fnm,O_RDONLY);
   Bfi = Det = NULL;
   if (h<0) break;
   if (Bfi=calloc(v+1,1)) {
      v = read(h,Bfi,v);
      close(h);
      remove(Fnm);
      Det = myConvertString(NULL,Bfi);
      free(Bfi);
      }
   } while (0);
else {
   Bfi = NULL;
   Det = CAS_getLastParamValue(Conn,"Det");
   Det = myConvertString(Conn,Det);
   }
if (Det) {
   CAS_nPrintf(Conn,Htmf,"",Inf,Det);
   if (Bfi) free(Det);
   }
else CAS_nPrintf(Conn,strerror(errno),"","");
}

void CAS_registerUserSettings(void) {
CAS_Srvinfo.preq = processRequest;
CAS_Srvinfo.cnfg = userConfig;
CAS_Srvinfo.html = manageHtmlFiles;
CAS_Srvinfo.ss = sizeof(T_userssn);
}
