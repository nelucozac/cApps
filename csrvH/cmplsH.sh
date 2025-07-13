gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/noSession.c csrvH.c -lpthread -o csrvH
chmod 700 csrvH
strip csrvH
