gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/noSession.c csrvB.c -lpthread -o csrvB
chmod 700 csrvB
strip csrvB
