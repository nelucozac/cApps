#include "cAppserver.h"

typedef struct {
        char *Sva;
        time_t etm;
        char Unm[12];
        } T_userssn;

static char *Users[] = { "Andrew", "Belinda", NULL } ;

static struct {
       char *Lgn, *Hom;
       } Htmf;

static void manageHtmlPages(char op) {
if (op=='L') {
   Htmf.Lgn = CAS_loadTextFile("Loginm.htm");
   Htmf.Hom = CAS_loadTextFile("Homepm.htm");
   }
else {
   free(Htmf.Lgn);
   free(Htmf.Hom);
   }
}

static int acceptPostLoad(CAS_srvconn_t *Conn, int cl, int le) {
T_userssn *Ussn;
char *Sva;
if (Conn->Bfi[0]!='P') return Conn->Ssn != NULL;
return Conn->Ssn ? 1 : cl <= 48;
}

static int checkIfLoginOk(CAS_srvconn_t *Conn) {
char *Uname, *Ulogn;
T_userssn *Ussn;
int k;
Uname = CAS_getLastParamValue(Conn,"Uname");
for (k=0; Ulogn=Users[k]; k++)
    if (strcmp(Users[k],Uname)==0) {
       CAS_createSession(Conn,CAS_Srvinfo.Rh[3]);
       Ussn = Conn->Ssn;
       if (Ussn==NULL) return -1;
       strcpy(Ussn->Unm,Ulogn);
       return 1;
       }
return 0;
}

static void displayLoginPage(CAS_srvconn_t *Conn, char *Msg) {
CAS_resetOutputBuffer(Conn);
CAS_nPrintf(Conn,CAS_Srvinfo.Rh[3],"");
CAS_nPrintf(Conn,Htmf.Lgn,Msg);
}

static void displayHomePage(CAS_srvconn_t *Conn) {
T_userssn *Ussn;
char *Str;
Ussn = Conn->Ssn;
Str = CAS_getLastParamValue(Conn,"Str");
Str = CAS_convertString(Conn,Str,'H');
CAS_nPrintf(Conn,Htmf.Hom,CAS_Srvinfo.fs,Ussn->Unm,Str,CAS_Srvinfo.fs);
}

static void uploadAction(CAS_srvconn_t *Conn) {
T_userssn *Ussn;
char *Dfi;
Ussn = Conn->Ssn;
Dfi = CAS_sPrintf(Conn,"%s/%s",Ussn->Unm,Conn->Ufn);
mkdir(Ussn->Unm,0700);
rename(Conn->Ufn,Dfi);
CAS_nPrintf(Conn,"File uploaded");
}

static void processRequest(CAS_srvconn_t *Conn) {
char *Act,*Msg;
int k;
if (Conn->Bfi[0]=='L') {
   uploadAction(Conn);
   return;
   }
Act = CAS_getLastParamValue(Conn,"Action");
if (strcmp(Act,"Login")==0) {
   k = checkIfLoginOk(Conn);
   switch (k) {
          case 1:  displayHomePage(Conn);
                   break;
          case 0:  displayLoginPage(Conn,"Incorrect name");
                   break;
          case -1: displayLoginPage(Conn,strerror_r(errno,Conn->Pct,1023));
                   break;
          }
   return;
   }
CAS_checkSession(Conn);
if (strcmp(Act,"Logout")==0) {
   CAS_deleteSession(Conn,NULL);
   displayLoginPage(Conn,"");
   return;
   }
if (Conn->Ssn==NULL) {
   Msg = errno == 0 ? "" : strerror_r(errno,Conn->Pct,1023);
   displayLoginPage(Conn,Msg);
   return;
   }
displayHomePage(Conn);
}

void CAS_registerUserSettings(void) {
CAS_Srvinfo.preq = processRequest;
CAS_Srvinfo.html = manageHtmlPages;
CAS_Srvinfo.post = acceptPostLoad;
CAS_Srvinfo.ss = sizeof(T_userssn);
}
