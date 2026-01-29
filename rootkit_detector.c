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
                // Tries to read the process's name
                char path[64], name[64];
                snprintf(path, sizeof(path), "/proc/%d/comm", pid);
                FILE *f = fopen(path, "r");
		if(f){
			if(fgets(name, sizeof(name), f)){
				name[strcspn(name, "\n")] = 0;
				// Checks out if it is a thread reading /proc/[pid]/status
				char status_path[64], line[128];
				int tgid = 0; // TGID = Thread Group ID
				snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
				FILE *fs = fopen(status_path, "r"); // fs = file stream
				if (fs){
					while(fgets(line, sizeof(line), fs)) {
						if(strncmp(line, "Tgid:", 5) == 0){
							tgid = atoi(line + 6);
							break;
						}
					}
					fclose(fs);
				}
				// If PID !=  TGID, it means that it is a thread.
				if(tgid == pid){
					printf("[!] ALERT: REAL Hidden Process detected: %d [%s]\n", pid, name);
					hidden_count++;
				}
			}
			fclose(f);
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
