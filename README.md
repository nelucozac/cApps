## Framework: developing C application servers (cApps) ##

(*only for Linux*)

This online distribution includes:
- main directory, the following files: cAppserver.c, cAppserver.h, cAppserver.cfg, Stack.c, Sortlog.c;
- csrvA to csrvJ directories: examples about how to develop your own C application server (GET requests);
- dsrvK to dsrvO directories: examples about how to develop your own C application server (POST requests);
- dsrvP directory: web application based on cApps framework;
- esrvX: the https support;
- cApps-get.pdf documentation, which details every example from csrvA to csrvJ;
- cApps-post.pdf documentation, which details every example from dsrvK to esrvX.

### **cApps-get.pdf** documentation ###

The examples cover a lot of problems which can be solved using this framework:
- obtaining GET parameters (URL) and header messages;
- sending files to client / browser;
- generating tables with variable number of rows and / or columns;
- complex problems: concurrent access to a big file using fast mutexes;
- developing benchmark program to evaluate the performances of your application server;
- using complex data structures: determining an optimum path in a graph;
- using your own log file to record every request coming from clients;
- denying requests coming from some particular Ip addresses;
- developing your own functions to create strings without memory allocation / deallocation (dealing with temporary strings);
- using mysql databases;
- basic authentication, together with Base64 encoding and decoding functions;
- session support (with and without cookies);
- protection against slowloris attack;
- how to upload files on server;
- https support.

Every example includes all the necessary files to build and run the application server:
C source files, compile scripts, configuration files, data files (if necessary) etc.
