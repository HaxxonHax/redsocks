#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
 
int gethostfromip(char *ip_addr, char *dest);
