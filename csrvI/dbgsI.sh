gcc -g -I../main/ ../main/cAppserver.c ../main/noSession.c `mysql_config --cflags` csrvI.c `mysql_config --libs` -lpthread -lm -o csrvI
chmod 700 csrvI
