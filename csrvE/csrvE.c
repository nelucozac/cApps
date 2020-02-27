/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

static int Limit, Ncols;
static char *Htm;

static void userConfig(char *Cfg) {
sscanf(Cfg,"%d %d",&Limit,&Ncols);
}

static void manageUserHtml(char op) {
if (op=='L') Htm = CAS_loadTextFile("Powers.htm");
   else free(Htm);
}

static void processRequest(CAS_srvconn_t *Conn) {
char m;
int n,c,i,j;
long long p;
struct { char *begin_htm, *begin_row, *head, *cell, *end_row, *end_htm; } Format;
n = atoi(CAS_getLastParamValue(Conn,"n"));
c = atoi(CAS_getLastParamValue(Conn,"c"));
if (n<0) n = 0;
if (n>Limit) n = Limit;
if (n>0) {
   if (c<2) c = 2;
   if (c>Ncols) c = Ncols;
   }
CAS_explodeHtm(Htm,&Format,sizeof(Format));
CAS_nPrintf(Conn,Format.begin_htm,Limit,n,Ncols,c);
if (n>0) {
   CAS_nPrintf(Conn,Format.begin_row);
    for (j=1; j<=c; j++)
        CAS_nPrintf(Conn,Format.head,j);
   CAS_nPrintf(Conn,Format.end_row);
   }
for (i=1; i<=n; i++) {
    CAS_nPrintf(Conn,Format.begin_row);
    for (j=p=1; j<=c; j++) {
        p *= i;
        CAS_nPrintf(Conn,Format.cell,p);
        }
    CAS_nPrintf(Conn,Format.end_row);
    }
CAS_nPrintf(Conn,Format.end_htm);
}

void CAS_registerUserSettings(void) {
CAS_Srvinfo.preq = processRequest;
CAS_Srvinfo.cnfg = userConfig;
CAS_Srvinfo.html = manageUserHtml;
}
