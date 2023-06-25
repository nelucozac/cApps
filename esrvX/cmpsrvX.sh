gcc -O3 -D _Secure_application_server -I../main/ ../main/cAppserver.c ../main/noSession.c esrvX.c -lssl -lcrypto -lpthread -o esrvX
chmod 700 esrvX
strip esrvX
