gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/noSession.c csrvA.c -o csrvA
chmod 700 csrvA
strip csrvA
