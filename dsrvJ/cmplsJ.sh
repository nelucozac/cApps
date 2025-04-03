gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/flSession.c dsrvJ.c -lpthread -o dsrvJ
chmod 700 dsrvJ
strip dsrvJ
