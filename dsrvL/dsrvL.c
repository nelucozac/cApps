
#include "cAppserver.h"

static char *Htm;

static void manageHtmlFiles(char op) {
if (op=='L') Htm = CAS_loadTextFile("Upload.htm");
   else free(Htm);
}

static void processRequest(CAS_srvconn_t *Conn) {
char *Fnam;
if (Conn->Bfi[0]=='L') {
   Fnam = CAS_getLastParamValue(Conn,"fname");
   rename(Conn->Ufn,Fnam);
   CAS_nPrintf(Conn,"%s uploaded",Fnam);
   return;
   }
CAS_nPrintf(Conn,Htm,CAS_Srvinfo.fs,CAS_Srvinfo.fs);
}

void CAS_registerUserSettings(void) {
CAS_Srvinfo.preq = processRequest;
CAS_Srvinfo.html = manageHtmlFiles;
}
