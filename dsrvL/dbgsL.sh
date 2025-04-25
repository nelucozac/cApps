gcc -g -I../main/ ../main/cAppserver.c ../main/flSession.c dsrvL.c -lpthread -o dsrvL
gcc -g -I../main/ ../main/cAppserver.c ../main/flSession.c dPlus.c -lpthread -o dPlus
chmod 700 dsrvL dPlus
