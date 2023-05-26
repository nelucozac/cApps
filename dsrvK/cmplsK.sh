gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/flSession.c dsrvK.c -lpthread -o dsrvK
chmod 700 dsrvK
strip dsrvK
