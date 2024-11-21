// OS ASSIGNMENT 04- MAKING SIMPLE SMART LOADER USING C FROM SCRATCH
// SUBMITTED BY:
// AARUSHI VERMA, 2023013
// VARSHA GANESH, 2023583

#include "loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <elf.h>
#define _GNU_SOURCE


// global variables to track execution stats and ELF headers
int count;
int pf_counter = 0; //page fault counter
double size = 0; //total memory size needed
double pg_alloc = 0; //pages allocated for each load
int pg_alloc_1 = 0; //total allocated pages
double frag = 0; //tracks memory fragments
Elf32_Ehdr *ehdr = NULL; //pointer to ELF header
Elf32_Phdr *phdr = NULL; //pointer to program headers
int fd, fd1; //file descriptors
int size1 = 0; //total memory size per segment
struct sigaction sa; //signal handler struct

// function declarations
void loader_cleanup();
void load_elf_header(int fd);
void load_program_headers(int fd);
void map_and_run_executable(int fd);
void run_entry_point(void *entry_point);
void close_file_descriptor(int fd);
int size_of_file(int mem);
void mmap_block(int fd, int prog, int signo, siginfo_t *si);


// frees memory allocated for the ELF header
void free_elf_header() {
    if (ehdr) {
        free(ehdr);
        ehdr = NULL;
    }
}

// frees memory allocated for the program headers
void free_program_headers() {
    if (phdr) {
        free(phdr);
        phdr = NULL;
    }
}

// overall cleanup function to free resources
void loader_cleanup() {
    free_elf_header();
    free_program_headers();
}


// safely unmaps memory at a specific address
void munmap_memory(void *addr, size_t length) {
    if (addr != MAP_FAILED) {
        munmap(addr, length);
    }
}


// calculates the required memory size rounded up to the nearest page size
int size_of_file(int mem) {
    while (1) {
        size += 4096;
        if (size >= mem) {
            break;
        }
    }
    return size;
}

// handles page fault by mapping required memory to the faulted address
void mmap_block(int fd, int prog, int signo, siginfo_t *si) {
    void *mem = mmap(si->si_addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (mem == MAP_FAILED) {
        perror("Memory mapping failed");
        close_file_descriptor(fd);
        exit(1);
    }
        // adjust the file descriptor to the program header's offset and read in one page of data
    lseek(fd, prog, SEEK_SET);
    if (read(fd, mem, 4096) < 0) {
        perror("Read error");
        munmap_memory(mem, size);
        close_file_descriptor(fd);
        exit(1);
    }
}

// loads the ELF header into memory
void load_elf_header(int fd) {
    ehdr = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
    if (!ehdr) {
        perror("Memory allocation error");
        close(fd);
        exit(1);
    }
    if (read(fd, ehdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
        perror("Error reading ELF header");
        free_elf_header();
        close(fd);
        exit(1);
    }
}

// handler function for segmentation faults (triggers page fault handling)
void segfault_handler(int signo, siginfo_t *si, void *context) {
    // void *mem = mmap(si->si_addr,4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,  fd,0);
    // lseek(fd, phdr[count].p_offset, SEEK_SET);
    // read(fd, mem, 4096);
    // printf("hii\n");
    // struct sigaction sa1;
    //  sa1.sa_sigaction = segfault_handler;
    //  sa1.sa_flags = SA_SIGINFO;
    // void *entry_point1;
    
    printf("Caught segfault at address %p\n", si->si_addr);
    double mem_alloc = 0;
     // loop through each loadable segment in the program headers
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if ((int)si->si_addr >= (int)phdr[i].p_vaddr &&
                (int)si->si_addr < (int)(phdr[i].p_vaddr + phdr[i].p_memsz)) {
                size = size_of_file(phdr[i].p_memsz);
                pg_alloc += size / 4096;
                pg_alloc_1 += size / 4096;
                size1 += phdr[i].p_memsz;
                // printf("virtual add %x\n",phdr[i].p_vaddr);
                mem_alloc = phdr[i].p_memsz;
                 // perror("x");
                    // sigaction(SIGSEGV,&sa,NULL);
                // int result = _start();
                    // perror("x");
                    // printf("output: %d\n", result);
                mmap_block(fd1, phdr[i].p_offset, signo, si);
                pf_counter++;
            }
        }
    }
    frag += (size - mem_alloc);
}

// loads the program headers into memory
void load_program_headers(int fd) {
    phdr = (Elf32_Phdr *)malloc(ehdr->e_phentsize * ehdr->e_phnum);
    if (!phdr) {
        perror("Memory allocation error");
        free_elf_header();
        close(fd);
        exit(1);
    }
    // move to the start of the program header table and read all entries
    lseek(fd, ehdr->e_phoff, SEEK_SET);
    if (read(fd, phdr, ehdr->e_phentsize * ehdr->e_phnum) != ehdr->e_phentsize * ehdr->e_phnum) {
        perror("Error reading program headers");
        free_program_headers();
        free_elf_header();
        close(fd);
        exit(1);
    }
}

// runs the program from its entry point
void run_entry_point(void *entry_point) {
    int (*_start)() = (int (*)())entry_point;
  
    struct sigaction sa1 = {0}; // setup segmentation fault handler
    sa1.sa_sigaction = segfault_handler;
    sa1.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa1, NULL);
    int result = _start(); // execute the entry point function
    printf("output: %d\n", result);
}

// safely closes a file descriptor
void close_file_descriptor(int fd) {
    if (fd != -1) {
        close(fd);
    }
}

void load_and_run_elf(char **exe) {
    fd = open(exe[1], O_RDONLY);
    if (fd == -1) {
        perror("Error opening file");
        exit(1);
    }

    load_elf_header(fd);
    load_program_headers(fd);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <executable>\n", argv[0]);
        exit(1);
    }

    sa.sa_sigaction = segfault_handler;  // initialize segmentation fault handler
    sa.sa_flags = SA_SIGINFO;
    fd1 = open(argv[1], O_RDONLY);
    if (fd1 == -1) {
        perror("Error opening file");
        exit(1);
    }

    sigaction(SIGSEGV, &sa, NULL); // apply handler
    load_and_run_elf(argv);  // load and execute the ELF file
    int (*_start)() = (int (*)())ehdr->e_entry;
    int result = _start();
    pg_alloc_1=pf_counter;
    printf("output: %d\n", result);
    // loader_cleanup();
    // printf("size: %d\n",ksize);
    printf("Number of Page Faults: %d\n", pf_counter); // print report
    printf("Number of allocated pages: %d\n", pg_alloc_1);
    printf("Fragmented memory size in KB: %f\n", frag / 1024);
    
     // cleanup resources
    close_file_descriptor(fd);
    close_file_descriptor(fd1);
    loader_cleanup();
    return 0;
}

