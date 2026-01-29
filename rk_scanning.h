#ifndef RK_SCANNING_H
#define RK_SCANNING_H

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>

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

static void scan_proc_dir() {
    DIR *dir;
    struct dirent *entry;
    // Opens /proc directory
    dir = opendir("/proc");
    if (dir == NULL){
        perror("[-] Failed to open /proc");
        return;
    }
    // Iterates over each directory entry
    while ((entry = readdir(dir)) != NULL) {
        // The program will look for PIDs. d_type == DT_DIR verifies if the file is a directory, and checks out if it is a digit as well (because PIDs are directories named as numbers)
        if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
            int pid = atoi(entry->d_name);
            // Marks the PID
            if(pid < MAX_PID){
                 mark_pid(pid);
             }
         }
     }

     closedir(dir);
     printf("[+] /proc scanning completed.\n");
 }

#endif
