#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
char* revv(const char* accept)
{
    char *res=(char*)calloc(strlen(accept), sizeof(char));
    strncpy(res, accept, strlen(accept));
    char * c1=res;
    char * c2=res+strlen(res)-1;
    while( c1 < c2)
    {
        /* swap */
        *c1 ^= *c2;
        *c2 ^= *c1;
        *c1 ^= *c2;
        c1++;
        c2--;
    }
    return res;
}

void trimback(char* accept)
{
    int t=strlen(accept)-strcspn(revv(accept), "/")-1;
    accept[t]='\0';
}
void hndl()
{
    return;
}
int main()
{
    signal(SIGINT, SIG_IGN);
    // char str[30]="./hello/file/sds/ds/sd/sd/sd/s";
    // trimback(str);
    // printf("%s", str);
    char c;
    c=getchar();
    printf("%c \n", c);
    return 0;
}
