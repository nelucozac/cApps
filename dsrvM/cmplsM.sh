gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/flSession.c dsrvM.c -lpthread -o dsrvM
chmod 700 dsrvM
strip dsrvM
