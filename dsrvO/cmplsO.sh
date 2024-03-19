gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/flSession.c dsrvO.c -lpthread -o dsrvO
chmod 700 dsrvO
strip dsrvO
