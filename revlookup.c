#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

int gethostfromip(char *ip_addr, char *dest) {
    struct sockaddr_in sa;
    char node[NI_MAXHOST];
 
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
     
    inet_pton(AF_INET, ip_addr, &sa.sin_addr);
    /* google-public-dns-a.google.com */
 
    int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa),
                          node, sizeof(node),
                          NULL, 0, NI_NAMEREQD);
    strcpy(dest,node); 
    if (res) {
        printf("error: %d\n", res);
        printf("%s\n", gai_strerror(res));
    }
    else
        printf("node=%s\n", node);
     
    return 0;
}
