/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

static void rewriteRules(CAS_srvconn_t *Conn) {
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
Cfg = CAS_buildMimeTypeList(Cfg);
/* Cfg points to the next information on this section */
}

static void processRequest(CAS_srvconn_t *Conn) {
char *Fnm;
if (Fnm=CAS_getParamValue(Conn,"File",NULL)) {
   CAS_sendFileToClient(Conn,Fnm,CAS_Srvinfo.Rh[2],NULL);
   return;
   }
CAS_nPrintf(Conn,"Vous n'avez pas demandé aucun fichier");
}

void CAS_registerUserSettings(void) {
CAS_Srvinfo.preq = processRequest;
CAS_Srvinfo.cnfg = userConfig;
CAS_Srvinfo.rwrl = rewriteRules;
}
