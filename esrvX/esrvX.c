/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

static void processRequest(CAS_srvconn_t *Conn) {
CAS_nPrintf(Conn,"<html><body>Hello world!</body></html>");
}

void CAS_registerUserSettings(void) {
CAS_Srvinfo.preq = processRequest;
}
