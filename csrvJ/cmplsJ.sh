gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/noSession.c csrvJ.c -o csrvJ
chmod 700 csrvJ
strip csrvJ
