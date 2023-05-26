gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/flSession.c dsrvL.c -lpthread -o dsrvL
chmod 700 dsrvL
strip dsrvL
