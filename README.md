## Framework: developing C application servers (cApps) ##

(*only for Linux*)

This online distribution includes:
- main directory, the following files: cAppserver.c, cAppserver.h, cAppserver.cfg, Stack.c;
- csrvA to csrvJ directories: examples about how to develop your own C application server;
- and cApps-get.pdf documentation, which details every example from csrvA to csrvJ.

### **cApps-get.pdf** documentation ###

The examples from csrvA to csrvJ cover a lot of problems which can be solved using this framework:
- obtaining GET parameters (URL) and header messages;
- sending files to client / browser;
- generating tables with variable number of rows and / or columns;
- complex problems: concurrent access to a big file using fast mutexes;
- developing benchmark program to evaluate the performances of your application server;
- using complex data structures: determining an optimum path in a graph;
- using your own log file to record every request coming from clients;
- denying requests coming from some particular Ip addresses;
- developing your own functions to create strings without memory allocation / deallocation (dealing with temporary strings);
- handling the timeout problem (time limit of the process exceeds);
- using mysql databases;
- basic authentication, together with Base64 encoding and decoding functions.

Every example includes all the necessary files to build and run the application server:
C source files, compile scripts, configuration files, data files (if necessary) etc.

-----

*At this time, only GET requests are used by these examples.*
*POST, LOAD requests and sessions are not yet documented.*

*However, you can use POST requests, see Appendix G* (*from cApps-get.pdf document*) *for details.*

*Coming soon:*
- *details about how to manage POST requests;*
- *session support;*
- *LOAD* (*ad-hoc created*) *method to upload files to server;*
- *https support.*
