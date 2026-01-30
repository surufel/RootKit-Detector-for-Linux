#ifndef RK_SCANNING_H
#define RK_SCANNING_H

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>

#define MAX_PID 32768 // 4KB
#define BITSET_SIZE (MAX_PID / 8) // Gets the max size of PIDs and divides by 1 byte, managing the PIDs and grabbing only their index.

// global Bitset to mark visible PIDs at /proc
uint8_t proc_pids[BITSET_SIZE]; // proc_pids = Processed PIDs

static void mark_pid(int pid){
     if(pid < MAX_PID){
         proc_pids[pid / 8] |= (1 << (pid % 8));
         // proc_pids[Which index it is located in the array, which byte] OR (|=) (1 << (shift left) (which bit))
     }
}

static bool is_marked(int pid){
     if(pid >= MAX_PID){return false;} // if it returns false, it is a rootkit.
     return proc_pids[pid / 8] & (1 << (pid % 8)); // Expected result is either 0 or x higher than 0. It grabs where is the processed PID, and bit-shifts 1 for (pid%8) times, and uses the &(AND) operator with the PID.
}

// Checks if the directory is numeric (a PID)
int is_pid_dir(const char *name) {
    while (*name) {
        if (*name < '0' || *name > '9') return 0;
        name++;
    }
    return 1;
}

static void scan_proc_dir(){
    DIR *dir = opendir("/proc");
    struct dirent *entry;
    if (!dir){return;}
    // Iterates over each directory entry
    while ((entry = readdir(dir)) != NULL){
	    printf("[LOG] Found entry: %s\n", entry->d_name);
        // The program will look for PIDs. d_type == DT_DIR verifies if the file is a directory, and checks out if it is a digit as well (because PIDs are directories named as numbers)
        if(entry->d_type == DT_DIR && is_pid_dir(entry->d_name)){
            int pid = atoi(entry->d_name);
            char path[64];
            snprintf(path, sizeof(path), "/proc/%d/status", pid);
	    struct stat st;
	    if(stat(path, &st) == 0){
		    mark_pid(pid);
         }
     }
    }
    closedir(dir);
    printf("[+] /proc scanning completed.\n");
}

#endif
