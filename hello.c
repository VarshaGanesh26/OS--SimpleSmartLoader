// segfault_test.c
#include <stdio.h>

int main() {
    printf("Testing segmentation fault handling.\n");

    // Create a large array to simulate memory access and trigger page faults
    int size = 1024 * 1024;
    int *array = (int *)malloc(size * sizeof(int));
    if (array == NULL) {
        perror("Memory allocation failed");
        return 1;
    }

    // Access memory to trigger page faults gradually
    for (int i = 0; i < size; i += 4096 / sizeof(int)) {
        array[i] = i;
    }

    printf("Segmentation fault test completed successfully.\n");
    free(array);
    return 0;
}

