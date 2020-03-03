/*
 License GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 This is free software: you are free to change and redistribute it.
 Determines how the stack is growing: downward or upward.
*/

#include <stdio.h>

static int stackDirection(double *A) {
double B[2];
A[0] = B[0] = 0;
return B < A;
}

int main() {
double A[2];
char *M;
M = stackDirection(A) ? "down" : "up";
printf("Stack grows %sward\n",M);
return 0;
}
