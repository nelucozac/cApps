gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/noSession.c csrvG.c -lpthread -o csrvG
chmod 700 csrvG
strip csrvG
