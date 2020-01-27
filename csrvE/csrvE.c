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
if (op=='L') Htm = loadTextFile("Powers.htm");
   else free(Htm);
}

static void processRequest(SRV_conn *Conn) {
char m;
int n,c,i,j;
long long p;
struct { char *begin_htm, *begin_row, *head, *cell, *end_row, *end_htm; } Format;
n = atoi(getLastParamValue(Conn,"n"));
c = atoi(getLastParamValue(Conn,"c"));
if (n<0) n = 0;
if (n>Limit) n = Limit;
if (n>0) {
   if (c<2) c = 2;
   if (c>Ncols) c = Ncols;
   }
explodeHtm(Htm,&Format,sizeof(Format));
nPrintf(Conn,Format.begin_htm,Limit,n,Ncols,c);
if (n>0) {
   nPrintf(Conn,Format.begin_row);
    for (j=1; j<=c; j++)
        nPrintf(Conn,Format.head,j);
   nPrintf(Conn,Format.end_row);
   }
for (i=1; i<=n; i++) {
    nPrintf(Conn,Format.begin_row);
    for (j=p=1; j<=c; j++) {
        p *= i;
        nPrintf(Conn,Format.cell,p);
        }
    nPrintf(Conn,Format.end_row);
    }
nPrintf(Conn,Format.end_htm);
}

void registerUserSettings(void) {
Srvinfo.preq = processRequest;
Srvinfo.cnfg = userConfig;
Srvinfo.html = manageUserHtml;
}
