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

void deep_scan_signals(){
    printf("[*] Starting deep scan for hidden processes...\n");
    int hidden_count = 0;

    for(int pid = 1; pid < MAX_PID; pid++){
        // Syscall for Kernel
        if(kill(pid, 0) == 0 || errno == EPERM){
            if (!is_marked(pid)){
                // Deals with false-positives
                usleep(1000);
                if(kill(pid, 0) == 0 || errno == EPERM){
                    printf("[!] ALERT: Hidden PID detected: %d\n", pid);
                    hidden_count++;
                }
            }
        }
    }
    printf("[+] Scan finished. Suspects found: %d\n", hidden_count);
}

int main() {
}
