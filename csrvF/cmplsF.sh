gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/noSession.c csrvF.c datsFc -lpthread -o csrvF
chmod 700 csrvF
strip csrvF
