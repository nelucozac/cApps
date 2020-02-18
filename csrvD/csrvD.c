/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

static int Limit;
static char *Htm, *Xml;

static void userConfig(char *Cfg) {
Limit = atoi(Cfg);
}

static void manageUserHtml(char op) {
if (op=='L') {
   Htm = loadTextFile("Numbers.htm");
   Xml = loadTextFile("Numbers.xml");
   }
else {
   free(Htm);
   free(Xml);
   }
}

static void processRequest(SRV_conn *Conn) {
char *Fmt;
int n,i,s;
long long c;
n = atoi(getLastParamValue(Conn,"n"));
if (n<0) n = 0;
if (n>Limit) n = Limit;
if (getParamValue(Conn,"Xml",NULL)) {
   resetOutputBuffer(Conn);
   nPrintf(Conn,Srvinfo.Rh[2]);
   Fmt = Xml;
   }
else Fmt = Htm;
nPrintf(Conn,Fmt,Limit,n,n);
Fmt = endOfString(Fmt,1);
for (i=1; i<=n; i++) {
    s = i * i;
    c = (long long)s * i;
    nPrintf(Conn,Fmt,i,s,c);
    }
Fmt = endOfString(Fmt,1);
nPrintf(Conn,Fmt);
}

void registerUserSettings(void) {
Srvinfo.preq = processRequest;
Srvinfo.cnfg = userConfig;
Srvinfo.html = manageUserHtml;
}
