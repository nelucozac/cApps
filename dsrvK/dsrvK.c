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
       char *Lgn, *Hom, *Slt, *Ins;
       } Htmf;

static void manageHtmlPages(char op) {
if (op=='L') {
   Htmf.Lgn = CAS_loadTextFile("Login.htm");
   Htmf.Hom = CAS_loadTextFile("Homepk.htm");
   Htmf.Slt = CAS_loadTextFile("Selectk.htm");
   Htmf.Ins = CAS_loadTextFile("Insertk.htm");
   }
else {
   free(Htmf.Lgn);
   free(Htmf.Hom);
   free(Htmf.Slt);
   free(Htmf.Ins);
   }
}

static char *getSessionValue(CAS_srvconn_t *Conn, char *Snam) {
char *Str;
Str = CAS_getHeaderValue(Conn,"Cookie");
if (Str==NULL) return NULL;
Str = strstr(Str,Snam);
if (Str==NULL) return NULL;
Str += strlen(Snam);
return *Str ? Str : NULL;
}

static int checkIfLoginOk(CAS_srvconn_t *Conn) {
char *Uname, *Ulogn;
T_userssn *Ussn;
int k;
Uname = CAS_getLastParamValue(Conn,"Uname");
for (k=0; Ulogn=Users[k]; k++)
    if (strcmp(Users[k],Uname)==0) {
       CAS_createSession(Conn);
       Ussn = Conn->Ssn;
       if (Ussn==NULL) return -1;
       strcpy(Ussn->Unm,Ulogn);
       return 1;
       }
return 0;
}

static T_userssn *preparePageWithSession(CAS_srvconn_t *Conn) {
T_userssn *Ussn;
CAS_resetOutputBuffer(Conn);
Ussn = Conn->Ssn;
CAS_nPrintf(Conn,CAS_Srvinfo.Rh[3],Ussn->Sva);
return Ussn;
}

static void displayLoginPage(CAS_srvconn_t *Conn, char *Msg) {
CAS_resetOutputBuffer(Conn);
CAS_nPrintf(Conn,CAS_Srvinfo.Rh[3],"");
CAS_nPrintf(Conn,Htmf.Lgn,Msg);
}

static void displayHomePage(CAS_srvconn_t *Conn) {
T_userssn *Ussn;
Ussn = preparePageWithSession(Conn);
CAS_nPrintf(Conn,Htmf.Hom,Ussn->Unm);
}

static void displaySelectPage(CAS_srvconn_t *Conn) {
T_userssn *Ussn;
char *Slt;
Ussn = preparePageWithSession(Conn);
Slt = CAS_getLastParamValue(Conn,"Select");
CAS_nPrintf(Conn,Htmf.Slt,Ussn->Unm,CAS_convertString(Conn,Slt,'H'));
}

static void displayInsertPage(CAS_srvconn_t *Conn) {
T_userssn *Ussn;
char *Ins;
Ussn = preparePageWithSession(Conn);
Ins = CAS_getLastParamValue(Conn,"Insert");
CAS_nPrintf(Conn,Htmf.Ins,Ussn->Unm,CAS_convertString(Conn,Ins,'H'));
}

static void processRequest(CAS_srvconn_t *Conn) {
char *Opt, *Sva, *Msg;
int k;
Opt = CAS_getLastParamValue(Conn,"Option");
if (strcmp(Opt,"Login")==0) {
   k = checkIfLoginOk(Conn);
   switch (k) {
          case 1: displayHomePage(Conn); break;
          case 0: displayLoginPage(Conn,"Incorrect name"); break;
          case -1: displayLoginPage(Conn,strerror(errno)); break;
          }
   return;
   }
Sva = getSessionValue(Conn,"MyApplicationSessionId=");
if (strcmp(Opt,"Logout")==0) {
   if (Sva) CAS_deleteSession(Conn,Sva);
   Sva = NULL;
   }
if (Sva==NULL) {
   displayLoginPage(Conn,"");
   return;
   }
CAS_checkSession(Conn,Sva);
if (Conn->Ssn==NULL) {
   Msg = errno == 0 ? "Session expired" : strerror(errno);
   displayLoginPage(Conn,Msg);
   return;
   }
if (strcmp(Opt,"Select")==0) {
   displaySelectPage(Conn);
   return;
   }
if (strcmp(Opt,"Insert")==0) {
   displayInsertPage(Conn);
   return;
   }
/* resolve other options
if (strcmp(Opt,"...") {
   page ...
   return;
   }
*/
displayHomePage(Conn);
}

void CAS_registerUserSettings(void) {
CAS_Srvinfo.preq = processRequest;
CAS_Srvinfo.html = manageHtmlPages;
CAS_Srvinfo.ss = sizeof(T_userssn);
}
