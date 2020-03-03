gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/noSession.c csrvD.c -o csrvD
chmod 700 csrvD
strip csrvD
;
