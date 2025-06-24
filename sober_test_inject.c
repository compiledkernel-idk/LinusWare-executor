#include <stdio.h>

__attribute__((constructor)) void init() {
    FILE *f = fopen("/tmp/sober_inject.log", "a");
    if (f) {
        fprintf(f, "Sober injected successfully.\n");
        fclose(f);
    }
}
