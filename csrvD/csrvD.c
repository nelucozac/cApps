/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/
//
#include "cAppserver.h"

static int Limit;
static char *Htm, *Xml;

static void userConfig(char *Cfg) {
Limit = atoi(Cfg);
}

static void manageUserHtml(char op) {
if (op=='L') {
   Htm = CAS_loadTextFile("Numbers.htm");
   Xml = CAS_loadTextFile("Numbers.xml");
   }
else {
   free(Htm);
   free(Xml);
   }
}

static void processRequest(CAS_srvconn_t *Conn) {
char *Fmt;
int n,i,s;
long long c;
n = atoi(CAS_getLastParamValue(Conn,"n"));
if (n<0) n = 0;
if (n>Limit) n = Limit;
if (CAS_getParamValue(Conn,"Xml",NULL)) {
   CAS_resetOutputBuffer(Conn);
   CAS_nPrintf(Conn,CAS_Srvinfo.Rh[2]);
   Fmt = Xml;
   }
else Fmt = Htm;
CAS_nPrintf(Conn,Fmt,Limit,n,n);
Fmt = CAS_endOfString(Fmt,1);
for (i=1; i<=n; i++) {
    s = i * i;
    c = (long long)s * i;
    CAS_nPrintf(Conn,Fmt,i,s,c);
    }
Fmt = CAS_endOfString(Fmt,1);
CAS_nPrintf(Conn,Fmt);
}

void CAS_registerUserSettings(void) {
CAS_Srvinfo.preq = processRequest;
CAS_Srvinfo.cnfg = userConfig;
CAS_Srvinfo.html = manageUserHtml;
}
