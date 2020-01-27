/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/

#include "cAppserver.h"

static void processRequest(SRV_conn *Conn) {
nPrintf(Conn,"Hello world!");
}

void registerUserSettings(void) {
Srvinfo.preq = processRequest;
}
