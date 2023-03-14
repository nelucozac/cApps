gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/noSession.c csrvE.c -lpthread -o csrvE
chmod 700 csrvE
strip csrvE 
