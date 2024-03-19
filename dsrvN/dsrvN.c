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
   Htmf.Hom = CAS_loadTextFile("Homepn.htm");
   Htmf.Slt = CAS_loadTextFile("Selectn.htm");
   Htmf.Ins = CAS_loadTextFile("Insertn.htm");
   }
else {
   free(Htmf.Lgn);
   free(Htmf.Hom);
   free(Htmf.Slt);
   free(Htmf.Ins);
   }
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

static void displayLoginPage(CAS_srvconn_t *Conn, char *Msg) {
CAS_nPrintf(Conn,Htmf.Lgn,Msg);
}

static void displayHomePage(CAS_srvconn_t *Conn) {
T_userssn *Ussn;
Ussn = Conn->Ssn;
CAS_nPrintf(Conn,Htmf.Hom,Ussn->Sva,Ussn->Unm);
}

static void displaySelectPage(CAS_srvconn_t *Conn) {
T_userssn *Ussn;
char *Slt;
Ussn = Conn->Ssn;
Slt = CAS_getLastParamValue(Conn,"Select");
CAS_nPrintf(Conn,Htmf.Slt,Ussn->Sva,Ussn->Unm,CAS_convertString(Conn,Slt,'H'));
}

static void displayInsertPage(CAS_srvconn_t *Conn) {
T_userssn *Ussn;
char *Ins;
Ussn = Conn->Ssn;
Ins = CAS_getLastParamValue(Conn,"Insert");
CAS_nPrintf(Conn,Htmf.Ins,Ussn->Sva,Ussn->Unm,CAS_convertString(Conn,Ins,'H'));
}

static void processRequest(CAS_srvconn_t *Conn) {
char *Act, *Sva, *Msg;
int k;
Act = CAS_getLastParamValue(Conn,"Action");
if (strcmp(Act,"Login")==0) {
   k = checkIfLoginOk(Conn);
   switch (k) {
          case 1: displayHomePage(Conn); break;
          case 0: displayLoginPage(Conn,"Incorrect name"); break;
          case -1: displayLoginPage(Conn,strerror(errno)); break;
          }
   return;
   }
if (Sva=CAS_getParamValue(Conn,"Token",NULL))
   CAS_checkSession(Conn,Sva);
if (strcmp(Act,"Logout")==0) {
   CAS_deleteSession(Conn);
   Sva = NULL;
   }
if (Sva==NULL) {
   displayLoginPage(Conn,"");
   return;
   }
if (Conn->Ssn==NULL) {
   Msg = errno == 0 ? "Session expired" : strerror(errno);
   displayLoginPage(Conn,Msg);
   return;
   }
if (strcmp(Act,"Select")==0) {
   displaySelectPage(Conn);
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
CAS_Srvinfo.ss = sizeof(T_userssn);
}
