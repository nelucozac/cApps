cApps (only for Linux)

Framework for developing C application servers

This online distribution includes:
- main directory, the following files: cAppserver.c, cAppserver.h, cAppserver.cfg, Stack.c;
- csrvA to csrvJ directories: examples about how to develop your own C application server;
- and cApps-get.pdf documentation, which details every example from csrvA to csrvJ.

The examples cover a lot of problems which can be solved using the framework:
- obtain GET parameters (URL) and header messages;
- send files to client / browser;
- generate tables with variable number of rows and / or columns;
- complex problems: concurrent access to a big file using fast mutexes;
- develop benchmark program to evaluate the performances of your application server;
- use complex data structures: determining an optimum path in a graph;
- use your own log file to record every request coming from clients;
- deny requests coming from some particular Ip addresses;
- develop your own functions which create and return strings without memory allocation /
  deallocation (dealing with temporary strings);
- manage the timeout problem: what to do when time limit to process the request exceeds;
- use mysql databases;
- basic authentication, together with Base64 encoding and decoding functions.

Every example includes all the necessary files to build and run the application server:
C source files, compile scripts, configuration files, data files (if necessary) etc.

---------------------------------------------------------------------------------------------

At this time, only GET requests are used by these examples.
POST requests and sessions are not yet documented.

However, you can use POST requests, see Appendix G (from cApps-get.pdf document) for details.

Coming soon:
- details about how to manage POST requests;
- session support;
- PUT method to upload files to server;
- https support.
