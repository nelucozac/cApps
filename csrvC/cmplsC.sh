gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/noSession.c csrvC.c -lpthread -o csrvC
chmod 700 csrvC
strip csrvC
