/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

static struct {
       unsigned char Ipn[16];
       int fLog, lAdr;
       } Config;

static void recordRequest(CAS_srvconn_t *Conn) {
char *Bf,*Pb,*P,*Q;
int l;
Bf = Conn->Pct;
inet_ntop(CAS_Srvinfo.af,Conn->Ipc,Bf,INET6_ADDRSTRLEN);
Pb = CAS_endOfString(Bf,0);
*Pb++ = ' ';
for (P=Conn->Bfi+5; *P; P++)
    if (isspace(*P)) break;
l = P - Conn->Bfi;
memcpy(Pb,Conn->Bfi,l);
Pb += l;
*Pb++ = '\n';
if (P=strcasestr(P,"User-agent:")) {
   Q = strpbrk(P,"\r\n");
   if (Q==NULL) Q = CAS_endOfString(P,0);
   l = Q - P;
   memcpy(Pb,P,l);
   Pb += l;
   }
*Pb++ = '\n';
*Pb++ = '\n';
l = write(Config.fLog,Bf,Pb-Bf);
}

static int acceptConnection(unsigned char *Ipc) {
return memcmp(Config.Ipn,Ipc,Config.lAdr) != 0;
}

static void userConfig(char *Cfg) {
char *P;
Config.lAdr = CAS_Srvinfo.af == AF_INET ? 4 : 16;
for (P=Cfg; *P; P++)
    if (isspace(*P)) break;
*P++ = 0;
inet_pton(CAS_Srvinfo.af,Cfg,Config.Ipn);
while (isspace(*P)) P++;
Cfg = P;
/* other user specific configuration data */
}

static char *concat(CAS_srvconn_t *Conn, ...) {
va_list Prms;
char *Pch,*Out;
int l;
va_start(Prms,Conn);
Out = Conn->Pct;
do {
   Pch = va_arg(Prms,char *);
   if (Pch==NULL) break;
   l = strlen(Pch);
   if (l==0) continue;
   if (Out+l>=Conn->Pet) return NULL;
   strcpy(Out,Pch);
   Out += l;
   } while (1);
va_end(Prms);
Pch = Conn->Pct;
Conn->Pct = Out + 1;
return Pch;
}

static char *stringToUpper(char *Str) {
char *P,c;
P = Str;
while (c=*P) {
      if (islower(c)) *P = toupper(c);
      P++;
      }
return Str;
}

static void processRequest(CAS_srvconn_t *Conn) {
char *A,*B,*C,*S;
A = "string A";
B = "string B";
C = "string C";
S = " - ";
CAS_nPrintf(Conn,"First concatenation: %s<br>",concat(Conn,A,S,B,S,C,NULL));
CAS_nPrintf(Conn,"Second concatenation: %s<br>",concat(Conn,B,S,C,A,NULL));
CAS_nPrintf(Conn,"%s<br>",stringToUpper(CAS_sPrintf(Conn,"%x",0xabcdef)));
}

void CAS_registerUserSettings(void) {
Config.fLog = open("csrvH.log",O_APPEND|O_CREAT|O_WRONLY|O_DSYNC,0600);
CAS_Srvinfo.rwrl = recordRequest;
CAS_Srvinfo.preq = processRequest;
CAS_Srvinfo.cnfg = userConfig;
CAS_Srvinfo.acco = acceptConnection;
}
