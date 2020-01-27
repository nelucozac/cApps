/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

static void rewriteRules(SRV_conn *Conn) {
char *P,c;
P = strchr(Conn->Bfi,'/') + 1;
if ((*P==0) || isspace(*P) || (*P=='?')) return;
memmove(P+6,P,strlen(P)+1);
memcpy(P,"?File=",6);
P = strchr(Conn->Bfi,'=') + 1;
do {
   c = *P;
   if (!c || isspace(c)) break;
   if (c=='?') {
      *P = '&';
      break;
      }
   P++;
   } while (1);
}

static void userConfig(char *Cfg) {
Cfg = buildMimeTypeList(Cfg);
/* Cfg points to the next information on this section */
}

static void processRequest(SRV_conn *Conn) {
char *Fnm;
if (Fnm=getParamValue(Conn,"File",NULL)) {
   sendFileToClient(Conn,Fnm,Srvinfo.Rh[2],NULL);
   return;
   }
nPrintf(Conn,"Vous n'avez pas demandé aucun fichier");
}

void registerUserSettings(void) {
Srvinfo.preq = processRequest;
Srvinfo.cnfg = userConfig;
Srvinfo.rwrl = rewriteRules;
}
