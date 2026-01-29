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
#include <string.h>

typedef struct {
    int pid;
    char status[20];
    bool is_hidden;
}suspectProcess;

void deep_scan_signals() {
    printf("[*] Starting deep scan for hidden processes...\n");
    int hidden_count = 0;

    for(int pid = 1; pid < MAX_PID; pid++){
        // Verifies if the PID exists
        if (kill(pid, 0) == 0 || errno == EPERM){
            	if(!is_marked(pid)){ // If Kernel confirms it exists in /procs, but it didn't got marked
				char path[64];
				snprintf(path, sizeof(path), "/proc/%d/status", pid);
				FILE *f = fopen(path, "r");
		if(f == NULL){
			printf("[!] ALERT: HIDDEN PID DETECTED (Inaccessible /proc): %d\n", pid);
			hidden_count++;
		} else {
			// If the file opens, we'll check if it is a TGID
			int tgid = -1;
			char line[128];
			while (fgets(line, sizeof(line), f)){
				if (strncmp(line, "Tgid:", 5) == 0){
							tgid = atoi(line + 6);
							break;
						}
					}
					fclose(f);

					if (tgid == pid) {
						printf("[!] ALERT: HIDDEN PROCESS DETECTED: %d\n", pid);
						hidden_count++;
					}
				}
		}
	}
}
printf("[+] Scan finished. Suspects found: %d\n", hidden_count);
}

int main(){
    if(geteuid() != 0){
        fprintf(stderr, "Error: Must run as root.\n");
        return 1;
    }
    // Initialize /proc scanning
    scan_proc_dir();
    // Compares
    deep_scan_signals();

    return 0;
}
