gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/flSession.c dsrvL.c -lpthread -o dsrvL
gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/flSession.c dPlus.c -lpthread -o dPlus
chmod 700 dsrvL dPlus
strip dsrvL dPlus
