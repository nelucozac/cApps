gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/flSession.c dsrvN.c -lpthread -o dsrvN
chmod 700 dsrvN
strip dsrvN
