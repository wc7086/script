#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

void genrnd(char *buff, int n)
{
    char metachar[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    struct timeval tv;
    gettimeofday(&tv,NULL);
    srand(tv.tv_sec*1000000 + tv.tv_usec);
    for (int i = 0; i < n; i++)
    {
        buff[i] = metachar[rand() % 62];
    }
    buff[n] = '\0';
}

int main(int argc, char *argv[])
{
    int tmp;
    sscanf(argv[1], "%d", &tmp);
    char r[tmp];
    genrnd(r, tmp);
    printf("%s\n", r);
    return 0;
}