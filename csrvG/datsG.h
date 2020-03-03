/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
*/
//
#include "cAppserver.h"

#ifndef _dat_tG_h

#define _dat_tG_h

typedef struct { int k; char *N; } T_nodeinf;

typedef struct { int s, c; } T_succinf;

typedef struct {
        int nn; /* number of graph nodes */
        int ml; /* maximum length of a node name */
        T_nodeinf *In; /* key and name of nodes from 1 to nn - In[1], In[2] etc */
        T_nodeinf **Ia; /* list nodes, alphabetically ordered - Ia[0], Ia[1] etc */
        T_succinf **Sc; /* lists of successors and costs */
        } T_graphinf;

extern T_graphinf Graph;

typedef struct {
        int *C; /* costs of paths from dep to x */
        int *P; /* previous node in a path from dep to x */
        int *Q; /* priority queue / nodes defining the path */
        int n;  /* number of elements in Q */
        signed char *E; /* -1 element not yet inserted in Q, 0 inserted, 1 removed */
        } T_vmark;

void minCostPath(int dep, int arv, T_vmark *Mk),
     manageUserData(char op);

#endif
