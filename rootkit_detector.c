#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <stdint.h>

#define MAX_PID 32768 // 4KB
#define BITSET_SIZE (MAX_PID / 8) // Gets the max size of PIDs and divides by 1 byte, managing the PIDs and grabbing only their index.

typedef struct {
    int pid;
    char status[20];
    bool is_hidden;
}suspectProcess;


// global Bitset to mark visible PIDs at /proc
uint8_t proc_pids[BITSET_SIZE]; // proc_pids = Processed PIDs

void mark_pid(int pid){
    if(pid < MAX_PID){
        proc_pids[pid / 8] |= (1 << (pid % 8));
        // proc_pids[Which index it is located in the array, which byte] OR (|=) (1 << (shift left) (which bit))
    }
}

bool is_marked(int pid){
    if(pid >= MAX_PID){return false;} // if it returns false, it is a rootkit.
    return proc_pids[pid / 8] & (1 << (pid % 8)); // Expected result is either 0 or x higher than 0. It grabs where is the processed PID, and bit-shifts 1 for (pid%8) times, and uses the &(AND) operator with the PID.
}

int main() {
}
