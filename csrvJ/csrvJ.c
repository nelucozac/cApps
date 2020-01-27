/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

static struct { char *Usr, *Pwd; } Auth;

static struct { signed char D[256], E[65]; } Base64;

static void userConfig(char *Cfg) {
char *P;
for (P=Cfg; isspace(*P)==0; P++) ;
Auth.Usr = P;
while (isspace(*P)==0) P++;
*P++ = 0;
for (P=Cfg; isspace(*P); P++) ;
Auth.Pwd = P;
while (isspace(*P)==0)
      if (*P) P++; else break;
*P++ = 0;
Cfg = P;
while (isspace(*Cfg)) Cfg++;
/* Cfg points to the next information on this section */
}

static char *encodeBase64(SRV_conn *Conn, unsigned char *Bin, int lbi) {
int k,l,b,c;
char *Out;
l = (lbi * 4 + 2) / 3;
if (c=l%4) l += 4 - c;
Out = Conn->Pct;
if (Out+l-1>=Conn->Pet) return NULL;
memset(Out,'=',l);
Out[l] = k = l = 0;
while (k<lbi) {
      Out[l++] = Base64.E[Bin[k]>>2];
      b = Bin[k++] % 4 << 4;
      c = k < lbi ? Bin[k] >> 4 : 0;
      Out[l++] = Base64.E[b+c];
      if (k>=lbi) break;
      b = Bin[k++] % 16 << 2;
      c = k < lbi ? Bin[k] >> 6 : 0;
      Out[l++] = Base64.E[b+c];
      if (k>=lbi) break;
      Out[l++] = Base64.E[Bin[k++]%64];
      }
Conn->Pct = Out + l;
return Out;
}

static char *decodeBase64(SRV_conn *Conn, char *Str) {
char *Out,*Dst,C[4];
unsigned char d;
int j;
if (Str=strchr(Str,' ')) Str++;
   else return NULL;
for (Dst=Str; d=(unsigned char)*Dst; Dst++)
    if (Base64.D[d]<0) break;
Out = Conn->Pct;
if (Out+(Dst-Str)>=Conn->Pet) return NULL;
memset(Out,0,Conn->Pet-Out);
Dst = Out;
while (Str) {
      C[0] = C[1] = C[2] = C[3] = 0;
      for (j=0; j<4; j++) {
          C[j] = d = *Str++;
          if (Base64.D[d]<0) {
             C[j] = 0;
             break;
             }
          }
      if (C[0]==0) break;
      d = Base64.D[C[0]];
      *Dst = d << 2;
      if (C[1]==0) break;
      d = Base64.D[C[1]];
      *Dst++ |= (d & 0x30) >> 4;
      *Dst = d << 4;
      if (C[2]==0) break;
      d = Base64.D[C[2]];
      *Dst++ |= d >> 2;
      *Dst = (d & 3) << 6;
      if (C[3]==0) break;
      d = Base64.D[C[3]];
      *Dst++ |= d;
      }
Conn->Pct = endOfString(Out,1);
return Out;
}

static void sendUnauthorized(SRV_conn *Conn) {
Conn->Pco = Conn->Bfo;
nPrintf(Conn,Srvinfo.Rh[2]);
nPrintf(Conn,"You must enter User name and Password");
}

static void processRequest(SRV_conn *Conn) {
char *Hau,*Pwd,*Str;
Hau = getHeaderValue(Conn,"Authorization");
if (Hau==NULL) {
   sendUnauthorized(Conn);
   return;
   }
nPrintf(Conn,"Header value : %s<br>",Hau);
Str = decodeBase64(Conn,Hau);
if (Str==NULL) {
   nPrintf(Conn,"Header malformed or not enough temporary buffer space");
   return;
   }
if (Pwd=strchr(Str,':')) {
   *Pwd++ = 0;
   if (!strcasecmp(Auth.Usr,Str) && !strcmp(Auth.Pwd,Pwd))
      nPrintf(Conn,"Ok, user name and password match");
   else
      nPrintf(Conn,"User name or password don't match");
   }
else
   nPrintf(Conn,"Can't obtain user name and password from header value");
}

void registerUserSettings(void) {
char *P;
int k;
Srvinfo.preq = processRequest;
Srvinfo.cnfg = userConfig;
memset(Base64.D,-1,sizeof(Base64.D));
for (k=0,P=Base64.E; k<64; k++,P++) {
    if (k<26) *P = k + 'A';
    else
    if (k<52) *P = k + 'a' - 26;
    else
    if (k<62) *P = k + '0' - 52;
    else *P = k == 62 ? '+' : '/';
    Base64.D[*P] = k;
    }
}
