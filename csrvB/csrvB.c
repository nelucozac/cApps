/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

static void processRequest(SRV_conn *Conn) {
char *Meth,*Sec,*Pnam,*Pval,Ip[INET6_ADDRSTRLEN];
struct tm Tim;
switch (Conn->Bfi[0]) {
       case 'G': Meth = "GET"; break;
       case 'P': Meth = "POST"; break;
       case 'U': Meth = "PUT"; break;
       }
Sec = Conn->Bfi[1] ? "secure" : "not secure";
nPrintf(Conn,"Method: %s, %s<br>",Meth,Sec);
nPrintf(Conn,"Unix time stamp (server): %D<br>\n",(long long)Conn->uts);
nPrintf(Conn,"Current date (yyyy/mm/dd) and time (hh:mm:ss) is: ");
localtime_r(&Conn->uts,&Tim);
nPrintf(Conn,"%d/%02d/%02d %02d:%02d:%02d<br><br>\n",
        Tim.tm_year,Tim.tm_mon,Tim.tm_mday,
        Tim.tm_hour,Tim.tm_min,Tim.tm_sec);
inet_ntop(Srvinfo.af,Conn->Ipc,Ip,sizeof(Ip));
nPrintf(Conn,"Ip address of client: %s<br>\nParameters<br>\n",Ip);
for (Pnam=NULL; Pnam=getParamName(Conn,Pnam); )
    for (Pval=NULL; Pval=getParamValue(Conn,Pnam,Pval); )
        nPrintf(Conn,"%s = %s<br>\n",Pnam,Pval);
Pnam = "a";
nPrintf(Conn,"<br>Last value of %s = %s",Pnam,getLastParamValue(Conn,Pnam));
nPrintf(Conn,"\n<br><br>Headers<br>");
for (Pnam=NULL; Pnam=getHeaderName(Conn,Pnam); )
    nPrintf(Conn,"%s : %s<br>\n",Pnam,getHeaderValue(Conn,Pnam));
Pnam = "uSer-aGent";
nPrintf(Conn,"<br>%s : %s<br><br>\n",Pnam,getHeaderValue(Conn,Pnam));
nPrintf(Conn,"Elapsed time : %.3e\n",getTime(NULL)-Conn->tim);
}

void registerUserSettings(void) {
Srvinfo.preq = processRequest;
}
