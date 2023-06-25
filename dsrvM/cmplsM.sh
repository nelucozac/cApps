gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/flSession.c dsrvM.c -lpthread -o dsrvM
gcc -O3 -D _Release_application_server -I../main/ ../main/cAppserver.c ../main/flSession.c dPlus.c -lpthread -o dPlus
chmod 700 dsrvM dPlus
strip dsrvM dPlus
