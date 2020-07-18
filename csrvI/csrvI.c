/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/
--
#include "cAppserver.h"
#include <my_global.h>
#include <mysql.h>

typedef struct { char *W; MYSQL *M; } T_userinf;

static struct { char *H, *D, *U, *P; } Myini;

static char *Fhtm;

static char *myGetString(char *Inp, char **Out) {
char *P,*Q;
P = Inp;
while (isspace(*P)) P++;
Q = P;
while (isspace(*Q)==0)
      if (*Q) Q++; else break;
*Q++ = 0;
*Out = P;
return Q;
}

static void userConfig(char *Cfg) {
Cfg = myGetString(Cfg,&Myini.H);
Cfg = myGetString(Cfg,&Myini.D);
Cfg = myGetString(Cfg,&Myini.U);
myGetString(Cfg,&Myini.P);
}

static void errorFromMysql(CAS_srvconn_t *Conn, char *Msg, char *Sql) {
T_userinf *Prms;
Prms = Conn->Usr;
if (Msg) CAS_nPrintf(Conn,"Mysql %s failed: error %u (%s)\n%s\n",Msg,(unsigned)mysql_errno(Prms->M),mysql_error(Prms->M),Sql);
   else CAS_nPrintf(Conn,"Mysql init failed (probably out of memory)\n");
}

static void manageUserHtml(char op) {
if (op=='L') Fhtm = CAS_loadTextFile("Dictio.htm");
   else free(Fhtm);
}

static MYSQL_RES *mysqlQueryResult(CAS_srvconn_t *Conn, char *Sql) {
T_userinf *Prms;
MYSQL_RES *Res;
Prms = Conn->Usr;
if (mysql_query(Prms->M,Sql)==0) {
   Res = mysql_store_result(Prms->M);
   if (Res==NULL) errorFromMysql(Conn,"store","");
   }
else {
   Res = NULL;
   errorFromMysql(Conn,"query",Sql);
   }
return Res;
}

static void displayHelp(CAS_srvconn_t *Conn) {
static char *sqlF = "select distinct wrd from Dictio where wrd like '%s%%' order by 1 limit 10";
char *sqlQ;
T_userinf *Prms;
MYSQL_RES *Res;
MYSQL_ROW Row;
int l;
Prms = Conn->Usr;
if (*Prms->W) do {
   l = strlen(sqlF) + strlen(Prms->W) + 1;
   sqlQ = Conn->Pet - l;
   sprintf(sqlQ,sqlF,Prms->W);
   Res = mysqlQueryResult(Conn,sqlQ);
   if (Res==NULL) break;
   while (Row=mysql_fetch_row(Res))
         CAS_nPrintf(Conn,"%s\n",Row[0]);
   mysql_free_result(Res);
   } while (0);
}

static void displayDefs(CAS_srvconn_t *Conn) {
static char *sqlF = "select def from Dictio where wrd='%s'";
char *Fmt,*sqlQ;
T_userinf *Prms;
MYSQL_RES *Res;
MYSQL_ROW Row;
int l;
Prms = Conn->Usr;
CAS_nPrintf(Conn,Fhtm,Prms->W);
Fmt = CAS_endOfString(Fhtm,1);
if (*Prms->W) do {
   l = strlen(sqlF) + strlen(Prms->W) + 1;
   sqlQ = Conn->Pet - l;
   sprintf(sqlQ,sqlF,Prms->W);
   Res = mysqlQueryResult(Conn,sqlQ);
   if (Res==NULL) break;
   while (Row=mysql_fetch_row(Res))
         CAS_nPrintf(Conn,Fmt,Prms->W,Row[0]);
   mysql_free_result(Res);
   } while (0);
Fmt = CAS_endOfString(Fmt,1);
CAS_nPrintf(Conn,Fmt,CAS_getTime(NULL)-Conn->tim);
}

static void strCopy(char *Ds, char *So, int ls) {
char c;
int k;
k = 0;
while (c=*So++) if (isalpha(c)) {
      *Ds++ = tolower(c);
      if (++k==ls) break;
      }
*Ds = 0;
}

static void processRequest(CAS_srvconn_t *Conn) {
T_userinf Prms;
char *P;
int l;
Conn->Usr = &Prms;
Prms.M = mysql_init(NULL);
if (Prms.M == NULL) {
   errorFromMysql(Conn,"","");
   return;
   }
if (mysql_real_connect(Prms.M,Myini.H,Myini.U,Myini.P,Myini.D,0,NULL,0)==NULL) {
   errorFromMysql(Conn,"connect","");
   return;
   }
P = CAS_getLastParamValue(Conn,"W");
l = strlen(P) + 1;
if (l>256) l = 256;
Prms.W = Conn->Pet - l - 2;
strCopy(Prms.W,P,l-1);
Conn->Pet -= l;
P = CAS_getLastParamValue(Conn,"O");
if (*P=='H') displayHelp(Conn);
   else displayDefs(Conn);
mysql_close(Prms.M);
}

void CAS_registerUserSettings(void) {
CAS_Srvinfo.cnfg = userConfig;
CAS_Srvinfo.preq = processRequest;
CAS_Srvinfo.html = manageUserHtml;
}
