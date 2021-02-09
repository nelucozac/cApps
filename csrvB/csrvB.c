/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

static void processRequest(CAS_srvconn_t *Conn) {
char *Meth,*Sec,*Pnam,*Pval,Ip[INET6_ADDRSTRLEN];
struct tm Tim;
switch (Conn->Bfi[0]) {
       case 'G': Meth = "GET"; break;
       case 'P': Meth = "POST"; break;
       case 'L': Meth = "LOAD"; break;
       }
Sec = Conn->Bfi[1] ? "secure" : "not secure";
CAS_nPrintf(Conn,"Method: %s, %s<br>",Meth,Sec);
CAS_nPrintf(Conn,"Unix time stamp (server): %D<br>\n",(long long)Conn->uts);
CAS_nPrintf(Conn,"Current date (yyyy/mm/dd) and time (hh:mm:ss) is: ");
localtime_r(&Conn->uts,&Tim);
CAS_nPrintf(Conn,"%d/%02d/%02d %02d:%02d:%02d<br><br>\n",Tim.tm_year+1900,Tim.tm_mon,
            Tim.tm_mday,Tim.tm_hour,Tim.tm_min,Tim.tm_sec);
inet_ntop(CAS_Srvinfo.af,Conn->Ipc,Ip,sizeof(Ip));
CAS_nPrintf(Conn,"Ip address of client: %s<br>\nParameters<br>\n",Ip);
for (Pnam=NULL; Pnam=CAS_getParamName(Conn,Pnam); )
    for (Pval=NULL; Pval=CAS_getParamValue(Conn,Pnam,Pval); )
        CAS_nPrintf(Conn,"%s = %s<br>\n",Pnam,Pval);
Pnam = "a";
CAS_nPrintf(Conn,"<br>Last value of %s = %s",Pnam,CAS_getLastParamValue(Conn,Pnam));
CAS_nPrintf(Conn,"\n<br><br>Headers<br>");
for (Pnam=NULL; Pnam=CAS_getHeaderName(Conn,Pnam); )
    CAS_nPrintf(Conn,"%s : %s<br>\n",Pnam,CAS_getHeaderValue(Conn,Pnam));
Pnam = "uSer-aGent";
CAS_nPrintf(Conn,"<br>%s : %s<br><br>\n",Pnam,CAS_getHeaderValue(Conn,Pnam));
CAS_nPrintf(Conn,"Elapsed time : %.3f\n",CAS_getTime(Conn));
}

void CAS_registerUserSettings(void) {
CAS_Srvinfo.preq = processRequest;
}
