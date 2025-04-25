/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

typedef struct {
        char *Sva;
        time_t etm;
        char Unm[12];
        } T_userssn;

static char *Users[] = { "Andrew", "Belinda", NULL } ;

static struct {
       char *Lgn, *Hom, *Ins;
       } Htmf;

static void manageHtmlPages(char op) {
if (op=='L') {
   Htmf.Lgn = CAS_loadTextFile("Logink.htm");
   Htmf.Hom = CAS_loadTextFile("Homepk.htm");
   Htmf.Ins = CAS_loadTextFile("Insertk.htm");
   }
else {
   free(Htmf.Lgn);
   free(Htmf.Hom);
   free(Htmf.Ins);
   }
}

static int acceptPost(CAS_srvconn_t *Conn, int cl, int le) {
T_userssn *Ussn;
char *Sva;
if (Conn->Bfi[0]!='P') return 0;
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
Ussn = Conn->Ssn;
CAS_nPrintf(Conn,Htmf.Hom,Ussn->Unm);
}

static void displayInsertPage(CAS_srvconn_t *Conn) {
T_userssn *Ussn;
char *Ins;
Ussn = Conn->Ssn;
Ins = CAS_getLastParamValue(Conn,"Insert");
CAS_nPrintf(Conn,Htmf.Ins,Ussn->Unm,CAS_convertString(Conn,Ins,'H'));
Ussn->etm = Conn->uts + 3600;
}

static void processRequest(CAS_srvconn_t *Conn) {
char *Act, *Sva, *Msg;
int k;
Act = CAS_getLastParamValue(Conn,"Action");
if (strcmp(Act,"Login")==0) {
   k = checkIfLoginOk(Conn);
   switch (k) {
          case 1:  displayHomePage(Conn);
                   break;
          case 0:  displayLoginPage(Conn,"User not found");
                   break;
          case -1: displayLoginPage(Conn,strerror_r(errno,Conn->Pct,1023));
                   break;
          }
   return;
   }
if (strcmp(Act,"Logout")==0) {
   CAS_deleteSession(Conn);
   displayLoginPage(Conn,"");
   return;
   }
CAS_checkSession(Conn);
if (Conn->Ssn==NULL) {
   Msg = errno ? strerror_r(errno,Conn->Pct,1023) : "";
   displayLoginPage(Conn,Msg);
   return;
   }
if (strcmp(Act,"Insert")==0) {
   displayInsertPage(Conn);
   return;
   }
displayHomePage(Conn);
}

void CAS_registerUserSettings(void) {
CAS_Srvinfo.preq = processRequest;
CAS_Srvinfo.html = manageHtmlPages;
CAS_Srvinfo.post = acceptPost;
CAS_Srvinfo.ss = sizeof(T_userssn);
}
