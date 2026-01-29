#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <ctype.h>
#include <stdint.h>
#include "rk_scanning.h"

typedef struct {
    int pid;
    char status[20];
    bool is_hidden;
}suspectProcess;

int main() {
}
