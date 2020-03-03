gcc -O3 -I../main/ Credic.c -o Credic
chmod 700 Credic
strip Credic
gcc -O3 -I../main/ Bmark.c -o bmDictio -lpthread
chmod 700 Bmark
strip Bmark
;
