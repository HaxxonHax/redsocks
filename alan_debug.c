#include <stdio.h>

void logdbgtofile(char *filename, char *logstring)
{
    FILE *fd = fopen(filename, "a+");
    fprintf(fd, "%s\n", logstring);
    fclose(fd);
}
